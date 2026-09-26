//! Real vlt locks (`tests/fixtures/vlt-locks/<version>/`, captured from every
//! era) through the hosted rewriter: only the target nodes' slots [2] and [3]
//! change, and the output stays in vlt's own canonical serialization, so
//! vlt's next save leaves it byte-identical. A CRLF checkout of each capture
//! gets the same edits, with every line keeping its `\r`.
//!
//! The vendored wiring runs against `tests/fixtures/vendor/npm/vlt/`, whose
//! expected locks real vlt wrote (`regenerate.sh`: an independent surgery,
//! then `vlt ci`), so byte equality proves `vlt ci` keeps the wired lock
//! byte-stable; the revert gives the pre-vendor bytes back. The lock
//! inventory reads the same captures.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord};
use socket_patch_core::patch::apply::PatchSources;
use socket_patch_core::patch::redirect::{rewrite_registry_redirect, DepOverride};
use socket_patch_core::vendor::lock_inventory::{inventory_project, LockIntegrity};
use socket_patch_core::vendor::npm_flavor::{revert_npm_any, vendor_npm_any};
use socket_patch_core::vendor::VendorOutcome;
use socket_patch_core::vendor::{save_state, VendorEntry, VendorState};

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

        let crlf: BTreeMap<String, String> = files
            .iter()
            .map(|(name, text)| (name.clone(), text.replace('\n', "\r\n")))
            .collect();
        let crlf_result = rewrite_registry_redirect(&crlf, &overrides);
        let crlf_codes: Vec<&str> = crlf_result
            .warnings
            .iter()
            .map(|w| w.code.as_str())
            .collect();
        assert_eq!(&crlf_codes, warnings, "{version}: CRLF");
        assert_eq!(
            crlf_result.files["vlt-lock.json"],
            output.replace('\n', "\r\n"),
            "{version}: CRLF"
        );
        assert_eq!(crlf_result.edits, result.edits, "{version}: CRLF");
    }
}

// ── vendored wiring ──────────────────────────────────────────────────────

const ORIGINAL_JS: &[u8] = b"module.exports = 'orig';\n";
const PATCHED_JS: &[u8] = b"module.exports = 'patched';\n";

fn vendor_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vendor/npm/vlt")
}

struct Case {
    version: String,
    name: String,
    dir: PathBuf,
    project: PathBuf,
    purl: String,
    uuid: String,
    refusal: Option<String>,
    churn: Vec<(String, String)>,
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for version in ["1.2.0", "1.0.10", "1.0.0-rc.14"] {
        let root = vendor_root().join(version);
        let mut names: Vec<String> = fs::read_dir(root.join("cases"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let dir = root.join("cases").join(&name);
            let case: Value =
                serde_json::from_str(&fs::read_to_string(dir.join("case.json")).unwrap()).unwrap();
            let churn = case["ciChurn"]
                .as_array()
                .map(|pairs| {
                    pairs
                        .iter()
                        .map(|p| {
                            (
                                p[0].as_str().unwrap().to_string(),
                                p[1].as_str().unwrap().to_string(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.push(Case {
                version: version.to_string(),
                project: root
                    .join("projects")
                    .join(case["project"].as_str().unwrap()),
                purl: case["purl"].as_str().unwrap().to_string(),
                uuid: case["uuid"].as_str().unwrap().to_string(),
                refusal: case["refusal"].as_str().map(str::to_string),
                churn,
                name,
                dir,
            });
        }
    }
    out
}

/// Every file under `dir`, relative, forward-slashed.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, fs::read(&path).unwrap());
            }
        }
    }
    out
}

fn write_tree(root: &Path, files: &BTreeMap<String, Vec<u8>>) {
    for (rel, bytes) in files {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
}

fn name_version(purl: &str) -> (String, String) {
    let rest = purl.strip_prefix("pkg:npm/").unwrap();
    let at = rest.rfind('@').unwrap();
    (rest[..at].to_string(), rest[at + 1..].to_string())
}

fn patch_record(uuid: &str) -> PatchRecord {
    let mut files = std::collections::HashMap::new();
    files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash: compute_git_sha256_from_bytes(ORIGINAL_JS),
            after_hash: compute_git_sha256_from_bytes(PATCHED_JS),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: String::new(),
        files,
        vulnerabilities: std::collections::HashMap::new(),
        description: String::new(),
        license: String::new(),
        tier: String::new(),
    }
}

/// A project staged from the case's inputs, an installed copy of the target
/// (with devDependencies, which the artifact must drop) and the patch blob.
struct Staged {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    installed: PathBuf,
    blobs: PathBuf,
}

fn stage(case: &Case, crlf: bool) -> Staged {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    let mut inputs = tree(&case.project);
    if crlf {
        let lock = String::from_utf8(inputs["vlt-lock.json"].clone()).unwrap();
        inputs.insert(
            "vlt-lock.json".into(),
            lock.replace('\n', "\r\n").into_bytes(),
        );
    }
    write_tree(&root, &inputs);
    let (name, version) = name_version(&case.purl);
    let installed = tmp.path().join("installed").join(&name);
    fs::create_dir_all(&installed).unwrap();
    fs::write(
        installed.join("package.json"),
        format!(
            "{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\",\n  \"devDependencies\": {{\n    \"tap\": \"1.0.0\"\n  }},\n  \"main\": \"index.js\"\n}}\n"
        ),
    )
    .unwrap();
    fs::write(installed.join("index.js"), ORIGINAL_JS).unwrap();
    let blobs = tmp.path().join("blobs");
    fs::create_dir_all(&blobs).unwrap();
    fs::write(
        blobs.join(compute_git_sha256_from_bytes(PATCHED_JS)),
        PATCHED_JS,
    )
    .unwrap();
    Staged {
        _tmp: tmp,
        root,
        installed,
        blobs,
    }
}

async fn vendor(case: &Case, staged: &Staged) -> VendorOutcome {
    let sources = PatchSources {
        blobs_path: &staged.blobs,
        packages_path: None,
        diffs_path: None,
        mem_blobs: None,
    };
    vendor_npm_any(
        &case.purl,
        &staged.installed,
        &staged.root,
        &patch_record(&case.uuid),
        &sources,
        "2026-09-26T00:00:00Z",
        false,
        false,
        None,
    )
    .await
}

fn apply_churn(lock: &str, churn: &[(String, String)]) -> String {
    let mut lines: Vec<String> = lock.split('\n').map(str::to_string).collect();
    for (from, to) in churn {
        let at = lines
            .iter()
            .position(|l| l.trim_end_matches(',') == from.trim_end_matches(','))
            .unwrap_or_else(|| panic!("no churned line {from}"));
        let comma = if lines[at].ends_with(',') { "," } else { "" };
        lines[at] = format!("{}{comma}", to.trim_end_matches(','));
    }
    lines.join("\n")
}

fn expected_files(case: &Case) -> BTreeMap<String, Vec<u8>> {
    let mut want = tree(&case.project);
    want.extend(tree(&case.dir.join("expected")));
    want
}

fn project_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    tree(root)
        .into_iter()
        .filter(|(rel, _)| !rel.starts_with(".socket/"))
        .collect()
}

fn expect_done(outcome: VendorOutcome, label: &str) -> VendorEntry {
    let VendorOutcome::Done {
        result,
        entry,
        warnings,
    } = outcome
    else {
        panic!("{label}: expected Done, got {outcome:?}");
    };
    assert!(result.success, "{label}: {:?}", result.error);
    assert!(
        warnings
            .iter()
            .all(|w| w.code != "vendor_multiple_lockfiles"),
        "{label}: {warnings:?}"
    );
    entry.unwrap_or_else(|| panic!("{label}: no ledger entry"))
}

#[test]
fn every_vendored_case_is_a_regenerated_fixture() {
    let all = cases();
    assert_eq!(all.len(), 33, "11 cases on each of 3 vlt versions");
    for case in &all {
        assert_eq!(
            case.refusal.is_none(),
            case.dir.join("expected/vlt-lock.json").is_file(),
            "{} {}",
            case.version,
            case.name
        );
    }
}

#[tokio::test]
async fn vendored_wiring_matches_what_vlt_ci_writes_and_reverts_byte_exact() {
    for case in cases() {
        let label = format!("{} {}", case.version, case.name);
        let staged = stage(&case, false);
        let before = project_files(&staged.root);
        let outcome = vendor(&case, &staged).await;
        if let Some(code) = &case.refusal {
            let VendorOutcome::Refused { code: got, detail } = outcome else {
                panic!("{label}: expected {code}, got {outcome:?}");
            };
            assert_eq!(got, code.as_str(), "{label}: {detail}");
            assert_eq!(
                project_files(&staged.root),
                before,
                "{label}: refusal writes nothing"
            );
            assert!(!staged.root.join(".socket").exists(), "{label}");
            continue;
        }
        let entry = expect_done(outcome, &label);
        let mut got = project_files(&staged.root);
        let lock = String::from_utf8(got["vlt-lock.json"].clone()).unwrap();
        got.insert(
            "vlt-lock.json".into(),
            apply_churn(&lock, &case.churn).into_bytes(),
        );
        let want = expected_files(&case);
        for (rel, bytes) in &want {
            assert_eq!(
                String::from_utf8_lossy(&got[rel]),
                String::from_utf8_lossy(bytes),
                "{label}: {rel}"
            );
        }
        assert_eq!(got.len(), want.len(), "{label}");

        let (name, version) = name_version(&case.purl);
        let rel_dir = entry.artifact.path.clone();
        assert!(
            rel_dir.ends_with(&format!("/node_modules/{name}")),
            "{label}: {rel_dir}"
        );
        assert_eq!(entry.flavor.as_deref(), Some("vlt"), "{label}");
        let inventory = entry.artifact.file_inventory.clone().expect("inventory");
        assert_eq!(
            inventory.keys().cloned().collect::<Vec<_>>(),
            ["index.js", "package.json"],
            "{label}"
        );
        let uuid_dir = staged
            .root
            .join(format!(".socket/vendor/npm/{}", case.uuid));
        assert_eq!(
            fs::read_to_string(uuid_dir.join(".gitignore")).unwrap(),
            "!*\n**/node_modules/*/node_modules/\n**/node_modules/@*/*/node_modules/\n"
        );
        assert_eq!(
            fs::read_to_string(uuid_dir.join(".gitattributes")).unwrap(),
            "* -text\n"
        );
        let artifact = staged.root.join(&rel_dir);
        assert_eq!(
            fs::read(artifact.join("index.js")).unwrap(),
            PATCHED_JS,
            "{label}"
        );
        assert_eq!(
            fs::read_to_string(artifact.join("package.json")).unwrap(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\",\n  \"main\": \"index.js\"\n}}\n"
            ),
            "{label}: devDependencies cut out as a span"
        );

        let mut state = VendorState::new();
        state.entries.insert(case.purl.clone(), entry.clone());
        save_state(&staged.root, &state).await.unwrap();
        let wired = project_files(&staged.root);
        match vendor(&case, &staged).await {
            VendorOutcome::Done {
                result,
                entry: None,
                ..
            } => assert!(result.success, "{label}"),
            other => panic!("{label}: a rerun is in sync, got {other:?}"),
        }
        assert_eq!(
            project_files(&staged.root),
            wired,
            "{label}: the rerun writes nothing"
        );

        let reverted = revert_npm_any(&entry, &staged.root, false).await;
        assert!(reverted.success, "{label}: {:?}", reverted.error);
        assert!(
            reverted.warnings.is_empty(),
            "{label}: {:?}",
            reverted.warnings
        );
        let mut after = project_files(&staged.root);
        after.remove(".socket/vendor/state.json");
        assert_eq!(
            after, before,
            "{label}: revert restores the pre-vendor bytes"
        );
        assert!(!uuid_dir.exists(), "{label}: the artifact is removed");
    }
}

#[tokio::test]
async fn revert_of_the_lock_vlt_ci_wrote_keeps_its_rewritten_outgoing_values() {
    for case in cases().into_iter().filter(|c| c.refusal.is_none()) {
        let label = format!("{} {}", case.version, case.name);
        let staged = stage(&case, false);
        let before = project_files(&staged.root);
        let entry = expect_done(vendor(&case, &staged).await, &label);
        write_tree(&staged.root, &tree(&case.dir.join("expected")));
        let reverted = revert_npm_any(&entry, &staged.root, false).await;
        assert!(reverted.success, "{label}: {:?}", reverted.error);
        assert!(
            !reverted.drift_skipped(),
            "{label}: {:?}",
            reverted.warnings
        );
        let got = project_files(&staged.root);
        let mut want = before.clone();
        if !case.churn.is_empty() {
            let lock = String::from_utf8(want["vlt-lock.json"].clone()).unwrap();
            let file_key = |line: &str| line.trim().split_once("\": ").unwrap().0.to_string();
            let value = |line: &str| {
                line.trim()
                    .trim_end_matches(',')
                    .split_once("\": ")
                    .unwrap()
                    .1
                    .to_string()
            };
            let mut lines: Vec<String> = lock.split('\n').map(str::to_string).collect();
            for (from, to) in &case.churn {
                let dep = file_key(from).rsplit_once(' ').unwrap().1.to_string();
                let at = lines
                    .iter()
                    .position(|l| l.contains(&format!(" {dep}\": {}", value(from))))
                    .unwrap_or_else(|| panic!("{label}: no pre-vendor twin of {from}"));
                lines[at] = lines[at].replace(&value(from), &value(to));
            }
            want.insert("vlt-lock.json".into(), lines.join("\n").into_bytes());
        }
        assert_eq!(got, want, "{label}");
    }
}

#[tokio::test]
async fn a_crlf_lock_is_wired_with_every_line_keeping_its_cr() {
    for case in cases()
        .into_iter()
        .filter(|c| c.refusal.is_none() && c.churn.is_empty())
    {
        let label = format!("{} {}", case.version, case.name);
        let staged = stage(&case, true);
        let before = project_files(&staged.root);
        let entry = expect_done(vendor(&case, &staged).await, &label);
        let want = fs::read_to_string(case.dir.join("expected/vlt-lock.json"))
            .unwrap()
            .replace('\n', "\r\n");
        assert_eq!(
            fs::read_to_string(staged.root.join("vlt-lock.json")).unwrap(),
            want,
            "{label}"
        );
        let reverted = revert_npm_any(&entry, &staged.root, false).await;
        assert!(reverted.success, "{label}: {:?}", reverted.error);
        assert_eq!(project_files(&staged.root), before, "{label}");
    }
}

#[tokio::test]
async fn lock_inventory_reads_every_capture_and_drops_vendored_nodes() {
    for (version, _, _) in CAPTURES {
        let tmp = tempfile::tempdir().unwrap();
        for (name, text) in read_capture(version) {
            fs::write(tmp.path().join(name), text).unwrap();
        }
        let lock: Value = serde_json::from_str(&read_capture(version)["vlt-lock.json"]).unwrap();
        let registry_nodes = lock["nodes"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with('~') || k.starts_with('·'))
            .count();
        let entries = inventory_project(tmp.path()).await;
        assert_eq!(entries.len(), registry_nodes, "{version}");
        for e in &entries {
            let url = e.resolved.as_deref().unwrap_or_default();
            let bare = e.name.rsplit('/').next().unwrap();
            assert!(
                url.ends_with(&format!("{bare}-{}.tgz", e.version)),
                "{version}: {} → {url}",
                e.purl
            );
            assert!(
                matches!(e.integrity, LockIntegrity::Sri(_)),
                "{version} {}",
                e.purl
            );
        }
    }

    let hosted = rewrite_registry_redirect(&read_capture("1.2.0"), &overrides());
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("vlt-lock.json"),
        &hosted.files["vlt-lock.json"],
    )
    .unwrap();
    let entries = inventory_project(tmp.path()).await;
    let left_pad = entries
        .iter()
        .find(|e| e.name == "left-pad" && e.version == "1.3.0")
        .expect("a hosted entry stays installed-by-lock");
    let uuid = TARGETS.iter().find(|t| t.0 == "left-pad").unwrap().2;
    assert_eq!(
        left_pad.resolved.as_deref(),
        Some(hosted_url("left-pad", "1.3.0", uuid).as_str())
    );
    assert_eq!(left_pad.integrity, LockIntegrity::Sri(patched_sha(uuid)));

    for case in cases().into_iter().filter(|c| c.refusal.is_none()) {
        let tmp = tempfile::tempdir().unwrap();
        write_tree(tmp.path(), &expected_files(&case));
        let (name, version) = name_version(&case.purl);
        let entries = inventory_project(tmp.path()).await;
        assert!(
            !entries
                .iter()
                .any(|e| e.name == name && e.version == version),
            "{} {}: the vendored file node is not a registry entry",
            case.version,
            case.name
        );
        assert!(!entries.is_empty(), "{} {}", case.version, case.name);
    }
}
