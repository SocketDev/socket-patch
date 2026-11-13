//! Hermetic CLI tests: `scan --prune` keeps what a lock that Bazel reads
//! resolves (design 3, hazard HZ-18).
//!
//! The prune drops the manifest record, and with it the blobs, of a
//! package the crawl does not find and no native lock lists. A package
//! that only a hub lock resolves (`maven_install.json` has no native
//! reader) is exactly that, and before this guard its record went with
//! exit 0 and no warning. Now a record a hub lock resolves stays, a
//! record of an ecosystem whose hub locks cannot all be listed stays and
//! the run says why, and everything else is pruned as it was.
//!
//! The built binary runs against a fake Socket API that knows no patch.
//! Nothing here depends on a lane: with none enabled the inventory reads
//! `maven_install.json` itself, and a lane that lands lists the same lock.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socket_patch_core::bazel::codes::Code;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::bazel_common::{assert_same_tree, assert_write_policy, snapshot};
use crate::common::envelope::{parse_json_envelope, warning_codes};
use crate::common::hermetic::{self, Extra};
use crate::common::{binary, git_sha256, hermetic_command, jvm_env, write_blob};

const ORG: &str = "test-org";
/// What the fixture's `maven_install.json` pins.
const GSON: &str = "pkg:maven/com.google.code.gson/gson@2.10.1";
/// A Maven release no lock anywhere resolves.
const ABSENT_JAR: &str = "pkg:maven/org.example/absent@1.0.0";
/// An npm release that is neither installed nor in a lock.
const STALE_NPM: &str = "pkg:npm/uninstalled@1.0.0";
/// rules_jvm_external is a dependency and no `maven.install` was read:
/// a hub may exist whose lock nobody listed.
const RULESET_NO_HUB: &str = "module(name = \"ws\")\n\
    bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n";
const PINNED_HUB: &str = "light/rules_jvm_external/bzlmod/e9";

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        match entry.file_type().unwrap().is_dir() {
            true => copy_tree(&entry.path(), &target),
            false => drop(std::fs::copy(entry.path(), &target).unwrap()),
        }
    }
}

/// The blob a record of `purl` holds: its bytes and where they are kept.
fn blob_of(root: &Path, purl: &str) -> (Vec<u8>, PathBuf) {
    let bytes = format!("patched bytes of {purl}\n").into_bytes();
    let at = root.join(".socket").join("blobs").join(git_sha256(&bytes));
    (bytes, at)
}

/// A checkout with one installed npm package (a prune judges against a
/// crawl that found something) and a manifest record, with its blob, for
/// each of `purls`. `fixture` is a workspace of the real-Bazel suite.
fn checkout(fixture: Option<&str>, purls: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    // `.git` bounds every upward read at the checkout.
    std::fs::create_dir_all(root.join(".git")).unwrap();
    if let Some(fixture) = fixture {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel");
        let from = fixture.split('/').fold(base, |dir, level| dir.join(level));
        copy_tree(&from, &root);
    }
    let installed = root.join("node_modules").join("fresh-pkg");
    std::fs::create_dir_all(&installed).unwrap();
    let package = r#"{ "name": "fresh-pkg", "version": "1.0.0" }"#;
    std::fs::write(installed.join("package.json"), package).unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "p", "version": "0.0.0" }"#,
    )
    .unwrap();

    let mut patches = serde_json::Map::new();
    for (at, purl) in purls.iter().enumerate() {
        let (bytes, _) = blob_of(&root, purl);
        write_blob(&root.join(".socket"), &git_sha256(&bytes), &bytes);
        let record = json!({
            "uuid": format!("{:08x}-1111-4111-8111-111111111111", at + 1),
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "package/patched": {
                "beforeHash": git_sha256(b"upstream bytes\n"),
                "afterHash": git_sha256(&bytes),
            }},
            "vulnerabilities": {},
            "description": "synthetic test patch",
            "license": "MIT",
            "tier": "free",
        });
        patches.insert((*purl).to_string(), record);
    }
    let manifest = serde_json::to_string_pretty(&json!({ "patches": patches })).unwrap();
    std::fs::write(root.join(".socket").join("manifest.json"), manifest).unwrap();
    (tmp, root)
}

/// A fake Socket API that knows no patch.
async fn fake_api() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    server
}

/// `scan --prune` in `root`: `(exit code, stdout, stderr)`.
fn prune(root: &Path, api: &MockServer, more: &[&str]) -> (i32, String, String) {
    let uri = api.uri();
    let fixed = [
        "scan",
        "--prune",
        "--yes",
        "--api-url",
        &uri,
        "--api-token",
        "fake",
        "--org",
        ORG,
    ];
    let mut cmd = hermetic_command(&binary());
    // No host virtualenv and no host JVM caches: an agent scan would
    // crawl them and ask the API about this machine's packages.
    hermetic::scrub_extra(&mut cmd, &[Extra::Venv]);
    jvm_env::isolate_cli(&mut cmd);
    cmd.args([&fixed[..], more].concat()).current_dir(root);
    let out = cmd.output().expect("run socket-patch");
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let code = out.status.code().unwrap_or(-1);
    (code, text(&out.stdout), text(&out.stderr))
}

/// `scan --prune --json`, dry or wet: the envelope of a run that exits 0.
fn prune_json(root: &Path, api: &MockServer, dry_run: bool) -> Value {
    let mut more = vec!["--json"];
    more.extend(dry_run.then_some("--dry-run"));
    let (code, stdout, stderr) = prune(root, api, &more);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    parse_json_envelope(&stdout)
}

/// The manifest records a run pruned (`removed`) or would (`verified`).
fn pruned(envelope: &Value, action: &str) -> Vec<String> {
    let events = envelope["events"].as_array().expect("events");
    let of_manifest = |e: &&Value| e["action"] == action && e["details"]["manifest"] == true;
    let purl = |e: &Value| e["purl"].as_str().expect("a purl").to_string();
    let mut purls: Vec<String> = events.iter().filter(of_manifest).map(purl).collect();
    purls.sort();
    purls
}

/// The purls the manifest on disk holds, sorted.
fn records(root: &Path) -> Vec<String> {
    let bytes = std::fs::read(root.join(".socket").join("manifest.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&bytes).unwrap();
    let patches = manifest["patches"].as_object().expect("patches");
    patches.keys().cloned().collect()
}

/// The details of the run's prune warnings.
fn kept_warnings(envelope: &Value) -> Vec<&str> {
    let code = Code::WorkspacePruneSkipped.as_str();
    let warnings = envelope["warnings"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let of_code = warnings.iter().filter(|w| w["code"] == code);
    of_code
        .map(|w| w["detail"].as_str().expect("a detail"))
        .collect()
}

/// Probe B5: the record of a package only `maven_install.json` resolves
/// was pruned with its blob. The lock is listed in full, so a record it
/// does not hold goes as before, and nothing needs saying.
#[tokio::test]
async fn a_record_a_hub_lock_resolves_is_kept_with_its_blob() {
    let (_tmp, root) = checkout(Some(PINNED_HUB), &[GSON, ABSENT_JAR]);
    let api = fake_api().await;
    let before = snapshot(&root);

    let dry = prune_json(&root, &api, true);
    assert_eq!(pruned(&dry, "verified"), [ABSENT_JAR], "{dry:#}");
    assert_eq!(kept_warnings(&dry), Vec::<&str>::new(), "{dry:#}");
    assert_same_tree(&before, &snapshot(&root));

    let wet = prune_json(&root, &api, false);
    assert_eq!(pruned(&wet, "removed"), [ABSENT_JAR], "{wet:#}");
    assert_eq!(kept_warnings(&wet), Vec::<&str>::new(), "{wet:#}");
    assert_eq!(records(&root), [GSON]);
    assert!(
        blob_of(&root, GSON).1.is_file(),
        "the kept record keeps its blob"
    );
    assert!(
        !blob_of(&root, ABSENT_JAR).1.exists(),
        "the pruned one does not"
    );
    assert_write_policy(&before, &snapshot(&root));
}

/// A lock of the ecosystem may exist that nobody listed: no Maven record
/// is pruned, the run says which and why, in the envelope and to a
/// person, and the npm record of the same manifest goes as before.
#[tokio::test]
async fn a_ruleset_with_no_hub_keeps_its_ecosystem_and_says_why() {
    let (_tmp, root) = checkout(None, &[ABSENT_JAR, STALE_NPM]);
    std::fs::write(root.join("MODULE.bazel"), RULESET_NO_HUB).unwrap();
    let api = fake_api().await;
    let before = snapshot(&root);

    let dry = prune_json(&root, &api, true);
    assert_eq!(pruned(&dry, "verified"), [STALE_NPM], "{dry:#}");
    let [said] = kept_warnings(&dry)[..] else {
        panic!("one prune warning expected in:\n{dry:#}");
    };
    assert!(said.starts_with("kept 1 manifest entry"), "{said}");
    assert!(
        said.contains(ABSENT_JAR) && !said.contains(STALE_NPM),
        "{said}"
    );
    assert_same_tree(&before, &snapshot(&root));

    // A person reads the same line.
    let (code, stdout, stderr) = prune(&root, &api, &["--dry-run"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains(&format!("GC: {said}.")), "{stdout}");
    assert_same_tree(&before, &snapshot(&root));

    let wet = prune_json(&root, &api, false);
    assert_eq!(pruned(&wet, "removed"), [STALE_NPM], "{wet:#}");
    assert_eq!(kept_warnings(&wet), [said], "{wet:#}");
    assert_eq!(records(&root), [ABSENT_JAR]);
    assert!(blob_of(&root, ABSENT_JAR).1.is_file());
    assert!(!blob_of(&root, STALE_NPM).1.exists());
    assert_write_policy(&before, &snapshot(&root));
}

/// The same manifest in a checkout with no Bazel file: every record goes
/// as it did, and no Bazel code is reported.
#[tokio::test]
async fn without_a_workspace_the_prune_is_what_it_was() {
    let (_tmp, root) = checkout(None, &[ABSENT_JAR, GSON, STALE_NPM]);
    let api = fake_api().await;
    let all = [GSON, ABSENT_JAR, STALE_NPM];
    let dry = prune_json(&root, &api, true);
    assert_eq!(pruned(&dry, "verified"), all, "{dry:#}");
    let wet = prune_json(&root, &api, false);
    assert_eq!(pruned(&wet, "removed"), all, "{wet:#}");
    assert_eq!(records(&root), Vec::<String>::new());
    for envelope in [&dry, &wet] {
        let bazel = |code: &String| code.contains("bazel");
        assert!(!warning_codes(envelope).iter().any(bazel), "{envelope:#}");
    }
}
