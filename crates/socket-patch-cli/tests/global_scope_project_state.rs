//! Global scope (`--global` / `--global-prefix`) never touches the `--cwd`
//! project's own hosted or vendored state (#436, #445).
//!
//! Global installs have no project lockfile, so a global run that starts
//! inside a project must leave that project's lockfile pins, vendored
//! wiring and vendor ledger alone, and the project's vendor ledger must not
//! decide ownership of a global copy:
//!
//! 1. `get` and `scan` refuse `--mode hosted|vendored` under global scope
//!    (usage error, exit 2) instead of rewiring the project (#436);
//! 2. `rollback -g` and `remove -g` leave a hosted project's pins (and its
//!    pre-v5 hosted ledger) as they were (#445);
//! 3. `rollback -g` and `remove -g` leave a vendored project's wiring,
//!    artifact and ledger as they were (#445);
//! 4. `apply -g` and `scan -g --mode agent` patch the global copy of a purl
//!    the project vendors (#445, the reverse direction);
//! 5. the standalone `vendor` command (plain, `--revert`, `--check`) is a
//!    usage error under global scope, so it neither vendors into nor
//!    reverts the project (#498).
//!
//! Binary-driven, `SOCKET_*`-scrubbed child processes (`common::run`).
//! Everything is offline except `scan`, which talks to a wiremock API.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

#[path = "common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::git_sha256;

const PATCH_HOST: &str = "http://patch.test";

fn run(root: &Path, args: &[&str]) -> (i32, String, String) {
    common::run_with_env(root, args, &[("SOCKET_PATCH_SERVER_URL", PATCH_HOST)])
}

fn parse(stdout: &str, stderr: &str) -> Value {
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected a JSON envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    })
}

/// An empty global prefix: a global run has nothing of its own to touch.
fn empty_prefix() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

// ═══════════════════════ 1. get / scan mode guard ═══════════════════════

/// `get -g --mode hosted|vendored` (and `--global-prefix`) is a usage error
/// before any network, and leaves the project's lockfile alone.
#[test]
fn get_refuses_project_modes_under_global_scope() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    let prefix = empty_prefix();
    let prefix = prefix.path().to_str().unwrap();
    for mode in ["hosted", "vendored"] {
        for (scope, flag) in [
            (vec!["--global"], "--global"),
            (vec!["--global-prefix", prefix], "--global-prefix"),
        ] {
            let mut args = vec!["get", "pkg:npm/left-pad@1.3.0", "--yes", "--mode", mode];
            args.extend(scope.iter().copied());
            let (code, stdout, stderr) = run(tmp.path(), &args);
            assert_eq!(code, 2, "{args:?}: stdout={stdout:?} stderr={stderr:?}");
            let expected = format!(
                "Error: {flag} cannot be used with --mode {mode}: global installs have no \
                 project lockfile to"
            );
            assert!(stderr.starts_with(&expected), "{args:?}: {stderr:?}");
            assert!(stdout.is_empty(), "{args:?}: {stdout:?}");

            args.push("--json");
            let (code, stdout, _) = run(tmp.path(), &args);
            assert_eq!(code, 2, "{args:?}");
            let v = parse(&stdout, "");
            assert_eq!(v["status"], "error", "{v}");
            assert!(
                v["error"]
                    .as_str()
                    .unwrap()
                    .starts_with(&expected["Error: ".len()..]),
                "{v}"
            );
        }
    }
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        "# yarn lockfile v1\n"
    );
    assert!(!tmp.path().join(".socket").exists(), "nothing written");
}

/// `scan -g --mode vendored` is a
/// usage error like `--mode hosted` already is.
#[test]
fn scan_refuses_vendored_mode_under_global_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let prefix = empty_prefix();
    let prefix = prefix.path().to_str().unwrap();
    for (args, flag) in [
        (vec!["scan", "--mode", "vendored", "--global"], "--global"),
        (
            vec!["scan", "--mode", "vendored", "--global-prefix", prefix],
            "--global-prefix",
        ),
    ] {
        let (code, stdout, stderr) = run(tmp.path(), &args);
        assert_eq!(code, 2, "{args:?}: stdout={stdout:?} stderr={stderr:?}");
        assert!(
            stderr.starts_with(&format!(
                "Error: {flag} cannot be used with --mode vendored: global installs have no \
                 project lockfile to wire vendored artifacts into"
            )),
            "{args:?}: {stderr:?}"
        );
        assert!(stdout.is_empty(), "{args:?}: {stdout:?}");
    }
    assert!(!tmp.path().join(".socket").exists(), "nothing written");
}

// ═══════════════════ 2. hosted project under rollback/remove -g ═══════════════════

const HOSTED_PURL: &str = "pkg:pypi/requests@2.31.0";
const WIRED_LINE: &str = "requests @ http://patch.test/patch/pypi/requests/2.31.0/22222222-2222-4222-8222-222222222222/a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1/requests-2.31.0-py3-none-any.whl --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn hosted_requirements() -> String {
    format!("flask==2.0.1\n{WIRED_LINE}\n")
}

/// A hosted-wired requirements.txt, a pre-v5 hosted ledger and an empty
/// manifest (so a global run gets past the "Manifest not found" check and
/// reaches its legs).
fn hosted_project() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("requirements.txt"), hosted_requirements()).unwrap();
    std::fs::create_dir_all(tmp.path().join(".socket/vendor")).unwrap();
    std::fs::write(
        tmp.path().join(".socket/manifest.json"),
        "{\n  \"patches\": {}\n}\n",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join(".socket/vendor/redirect-state.json"),
        serde_json::to_vec_pretty(&json!({ "version": 1, "records": {}, "edits": [] })).unwrap(),
    )
    .unwrap();
    tmp
}

fn assert_hosted_untouched(root: &Path, what: &str) {
    assert_eq!(
        std::fs::read_to_string(root.join("requirements.txt")).unwrap(),
        hosted_requirements(),
        "{what}: the project's hosted pin must stay wired"
    );
    assert!(
        root.join(".socket/vendor/redirect-state.json").is_file(),
        "{what}: the project's pre-v5 hosted ledger must not be retired"
    );
}

/// Control: a project-scoped rollback does restore the pin (so the global
/// assertions below are not vacuous).
#[test]
fn project_rollback_restores_the_hosted_pin() {
    let tmp = hosted_project();
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--yes", "--offline"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap(),
        "flask==2.0.1\nrequests==2.31.0\n"
    );
}

#[test]
fn global_rollback_leaves_hosted_project_pins() {
    let prefix = empty_prefix();
    let prefix = prefix.path().to_str().unwrap();
    for scope in [
        vec!["--global-prefix", prefix],
        vec!["--global", "--global-prefix", prefix],
    ] {
        let tmp = hosted_project();
        let mut args = vec!["rollback", "--json", "--yes", "--offline"];
        args.extend(scope.iter().copied());
        let (code, stdout, stderr) = run(tmp.path(), &args);
        assert_eq!(code, 0, "{args:?}: stdout={stdout}\nstderr={stderr}");
        let v = parse(&stdout, &stderr);
        assert_eq!(v["status"], "success", "{v}");
        assert_eq!(v["hosted"]["reverted"], json!([]), "{args:?}: {v}");
        assert_hosted_untouched(tmp.path(), &format!("{args:?}"));
    }
}

#[test]
fn global_remove_leaves_hosted_project_pins() {
    let prefix = empty_prefix();
    let prefix = prefix.path().to_str().unwrap();
    let tmp = hosted_project();
    let args = [
        "remove",
        HOSTED_PURL,
        "--json",
        "--yes",
        "--offline",
        "--global-prefix",
        prefix,
    ];
    let (code, stdout, stderr) = run(tmp.path(), &args);
    // The global scope holds no patch for the purl: not found.
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert_hosted_untouched(tmp.path(), "remove --global-prefix");
}

// ═══════════════════ 3. vendored project under rollback/remove -g ═══════════════════

const V_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const V_PURL: &str = "pkg:npm/left-pad@1.3.0";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

/// A vendored npm project: `vendor` (offline, the prebuilt artifact
/// service) wired `left-pad` into `.socket/vendor/` and recorded it in the
/// ledger; the manifest keeps its record.
struct VendoredProject {
    tmp: tempfile::TempDir,
    wired_lock: Vec<u8>,
    ledger: Vec<u8>,
}

impl VendoredProject {
    fn root(&self) -> &Path {
        self.tmp.path()
    }
    fn tgz(&self) -> PathBuf {
        self.root()
            .join(format!(".socket/vendor/npm/{V_UUID}/left-pad-1.3.0.tgz"))
    }
    fn assert_untouched(&self, what: &str) {
        assert_eq!(
            std::fs::read(self.root().join("package-lock.json")).unwrap(),
            self.wired_lock,
            "{what}: the project's vendored wiring must stay"
        );
        assert!(
            self.tgz().is_file(),
            "{what}: the vendored artifact must stay"
        );
        assert_eq!(
            std::fs::read(self.root().join(".socket/vendor/state.json")).unwrap(),
            self.ledger,
            "{what}: the vendor ledger must stay byte-identical"
        );
        assert_eq!(
            std::fs::read(self.root().join("node_modules/left-pad/index.js")).unwrap(),
            ORIG_INDEX,
            "{what}: the project's installed copy must stay"
        );
    }
    fn manifest(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.root().join(".socket/manifest.json")).unwrap())
            .unwrap()
    }
}

fn write_left_pad(dir: &Path, index: &[u8]) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("index.js"), index).unwrap();
}

/// The npm project `vendored_project` starts from: `left-pad` installed
/// from the registry, its patch recorded in the manifest, nothing vendored
/// yet. Returns the project and its original lockfile bytes.
fn manifest_project() -> (tempfile::TempDir, Vec<u8>) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    write_left_pad(&root.join("node_modules/left-pad"), ORIG_INDEX);
    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
                "license": "WTFPL"
            }
        }
    });
    let mut original_lock = serde_json::to_vec_pretty(&lock).unwrap();
    original_lock.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &original_lock).unwrap();

    let after_hash = git_sha256(PATCHED_INDEX);
    let manifest = json!({
        "patches": {
            V_PURL: {
                "uuid": V_UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": git_sha256(ORIG_INDEX),
                        "afterHash": after_hash
                    }
                },
                "vulnerabilities": {},
                "description": "synthetic global-scope patch",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(&after_hash), PATCHED_INDEX).unwrap();
    std::fs::write(
        socket.join("blobs").join(git_sha256(ORIG_INDEX)),
        ORIG_INDEX,
    )
    .unwrap();
    (tmp, original_lock)
}

fn vendored_project() -> VendoredProject {
    let (tmp, original_lock) = manifest_project();
    let root = tmp.path();
    let service = prebuilt_common::Server::project(root);
    let (code, stdout, stderr) = common::run_with_env(
        root,
        &["vendor", "--json", "--silent", "--lock-timeout", "5"],
        &[("SOCKET_VENDOR_URL", &service.uri)],
    );
    assert_eq!(
        code, 0,
        "fixture vendor: stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let wired_lock = std::fs::read(root.join("package-lock.json")).unwrap();
    assert_ne!(wired_lock, original_lock, "sanity: vendor rewired the lock");
    let ledger = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();
    let project = VendoredProject {
        tmp,
        wired_lock,
        ledger,
    };
    assert!(project.tgz().is_file(), "sanity: artifact written");
    project
}

#[test]
fn global_rollback_leaves_vendored_project_state() {
    let project = vendored_project();
    let prefix = empty_prefix();
    let (code, stdout, stderr) = run(
        project.root(),
        &[
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--global-prefix",
            prefix.path().to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse(&stdout, &stderr);
    assert_eq!(v["vendoredReverted"], json!([]), "{v}");
    project.assert_untouched("rollback --global-prefix");
    assert!(
        project.manifest()["patches"].get(V_PURL).is_some(),
        "the project's vendored record must stay in the manifest"
    );
}

#[test]
fn global_remove_leaves_vendored_project_state() {
    let project = vendored_project();
    let prefix = empty_prefix();
    let (code, stdout, stderr) = run(
        project.root(),
        &[
            "remove",
            V_PURL,
            "--json",
            "--yes",
            "--offline",
            "--global-prefix",
            prefix.path().to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    project.assert_untouched("remove --global-prefix");
}

// ═══════════════════ 4. a vendored purl's global copy is patched ═══════════════════

/// `apply --global-prefix` patches the global copy of a purl the project
/// vendors: the project's ledger owns the project's copy, not the global
/// one.
#[test]
fn global_apply_patches_a_purl_the_project_vendors() {
    let project = vendored_project();
    let prefix = empty_prefix();
    write_left_pad(&prefix.path().join("left-pad"), ORIG_INDEX);
    let (code, stdout, stderr) = run(
        project.root(),
        &[
            "apply",
            "--json",
            "--offline",
            "--global-prefix",
            prefix.path().to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert_eq!(
        std::fs::read(prefix.path().join("left-pad/index.js")).unwrap(),
        PATCHED_INDEX,
        "the global copy must be patched; stdout={stdout}"
    );
    project.assert_untouched("apply --global-prefix");
}

const ORG: &str = "test-org";

async fn mount_api(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": V_PURL,
                "patches": [{
                    "uuid": V_UUID, "purl": V_PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": ["GHSA-left-pad-0"],
                    "severity": "high", "title": "left-pad",
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    let vulns = json!({
        "GHSA-left-pad-0": { "cves": [], "summary": "s", "severity": "high", "description": "d" }
    });
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.*left-pad(%40|@)1\\.3\\.0$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [{
                "uuid": V_UUID, "purl": V_PURL, "publishedAt": "2026-01-01T00:00:00Z",
                "description": "left-pad", "license": "MIT", "tier": "free",
                "vulnerabilities": vulns,
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    use base64::Engine;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{V_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": V_UUID, "purl": V_PURL, "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": git_sha256(ORIG_INDEX),
                "afterHash": git_sha256(PATCHED_INDEX),
                "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED_INDEX),
            }},
            "vulnerabilities": vulns,
            "description": "left-pad", "license": "MIT", "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// `scan -g --mode agent` patches the global copy of a purl the project
/// vendors instead of skipping it as `vendored_ownership_retained`.
#[tokio::test]
async fn global_agent_scan_patches_a_purl_the_project_vendors() {
    let project = vendored_project();
    // v5 vendored mode is manifest-free: the ledger alone records the
    // patch, so nothing marks the global copy as already patched.
    std::fs::write(
        project.root().join(".socket/manifest.json"),
        "{\n  \"patches\": {}\n}\n",
    )
    .unwrap();
    let prefix = empty_prefix();
    write_left_pad(&prefix.path().join("left-pad"), ORIG_INDEX);
    let mock = MockServer::start().await;
    mount_api(&mock).await;
    let uri = mock.uri();
    let (code, stdout, stderr) = run(
        project.root(),
        &[
            "scan",
            "--json",
            "--yes",
            "--mode",
            "agent",
            "--global-prefix",
            prefix.path().to_str().unwrap(),
            "--api-url",
            &uri,
            "--api-token",
            "fake-token",
            "--org",
            ORG,
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse(&stdout, &stderr);
    let codes: Vec<&str> = v["warnings"]
        .as_array()
        .map(|w| w.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        !codes.contains(&"vendored_ownership_retained"),
        "the project's ledger must not own the global copy: {v}"
    );
    assert_eq!(
        std::fs::read(prefix.path().join("left-pad/index.js")).unwrap(),
        PATCHED_INDEX,
        "the global copy must be patched: {v}"
    );
    project.assert_untouched("scan --global-prefix --mode agent");
}

// ═══════════════════ 5. the vendor command under global scope ═══════════════════

/// Every way to ask for global scope: the flags and their env vars.
fn global_scopes(prefix: &str) -> Vec<(Vec<&str>, Vec<(&'static str, String)>, &'static str)> {
    vec![
        (vec!["--global"], vec![], "--global"),
        (vec!["-g"], vec![], "--global"),
        (vec!["--global-prefix", prefix], vec![], "--global-prefix"),
        (vec![], vec![("SOCKET_GLOBAL", "1".to_string())], "--global"),
        (
            vec![],
            vec![("SOCKET_GLOBAL_PREFIX", prefix.to_string())],
            "--global-prefix",
        ),
    ]
}

/// Run `vendor <extra>` under every global scope, human and `--json`, and
/// assert each is the exit-2 usage error naming `why`.
fn assert_vendor_refused(root: &Path, extra: &[&str], why: &str, mut after_each: impl FnMut(&str)) {
    let prefix = empty_prefix();
    let prefix = prefix.path().to_str().unwrap();
    for (flags, env, flag) in global_scopes(prefix) {
        for json in [false, true] {
            let mut args = vec!["vendor", "--yes", "--offline", "--lock-timeout", "5"];
            args.extend(extra.iter().copied());
            args.extend(flags.iter().copied());
            if json {
                args.push("--json");
            }
            let mut envs: Vec<(&str, &str)> = vec![("SOCKET_PATCH_SERVER_URL", PATCH_HOST)];
            envs.extend(env.iter().map(|(k, v)| (*k, v.as_str())));
            let (code, stdout, stderr) = common::run_with_env(root, &args, &envs);
            let what = format!("{args:?} {env:?}");
            assert_eq!(code, 2, "{what}: stdout={stdout}\nstderr={stderr}");
            let expected = format!(
                "{flag} cannot be used with vendor{}: global installs have no project \
                 lockfile to {why}",
                extra.first().map(|f| format!(" {f}")).unwrap_or_default()
            );
            if json {
                let v = parse(&stdout, &stderr);
                assert_eq!(v["status"], "error", "{what}: {v}");
                assert_eq!(
                    v["error"]["code"], "global_scope_unsupported",
                    "{what}: {v}"
                );
                assert_eq!(v["error"]["message"], expected.as_str(), "{what}: {v}");
            } else {
                assert_eq!(stderr.trim_end(), format!("Error: {expected}"), "{what}");
                assert!(stdout.is_empty(), "{what}: {stdout:?}");
            }
            after_each(&what);
        }
    }
}

/// `vendor --revert -g` inside a vendored project must not revert the
/// project's vendoring (#498): that silently unpatched it on the next
/// frozen install.
#[test]
fn global_vendor_revert_leaves_vendored_project_state() {
    let project = vendored_project();
    assert_vendor_refused(
        project.root(),
        &["--revert"],
        "revert vendored artifacts from",
        |what| project.assert_untouched(what),
    );
    // Control: the same revert without global scope does unwind it.
    let (code, stdout, stderr) = run(
        project.root(),
        &[
            "vendor",
            "--revert",
            "--yes",
            "--json",
            "--lock-timeout",
            "5",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(!project.tgz().exists(), "control: project revert unwinds");
}

/// `vendor -g` inside a project whose manifest holds a record (e.g. one
/// `get -g` wrote) must not vendor into the project (#498).
#[test]
fn global_vendor_does_not_vendor_into_the_project() {
    let (tmp, original_lock) = manifest_project();
    let root = tmp.path();
    let service = prebuilt_common::Server::project(root);
    let manifest = std::fs::read(root.join(".socket/manifest.json")).unwrap();
    let prefix = empty_prefix();
    let prefix = prefix.path().to_str().unwrap();
    for (flags, env, flag) in global_scopes(prefix) {
        let mut args = vec!["vendor", "--json", "--lock-timeout", "5"];
        args.extend(flags.iter().copied());
        let mut envs: Vec<(&str, &str)> = vec![("SOCKET_VENDOR_URL", &service.uri)];
        envs.extend(env.iter().map(|(k, v)| (*k, v.as_str())));
        let (code, stdout, stderr) = common::run_with_env(root, &args, &envs);
        let what = format!("{args:?} {env:?}");
        assert_eq!(code, 2, "{what}: stdout={stdout}\nstderr={stderr}");
        let v = parse(&stdout, &stderr);
        assert_eq!(
            v["error"]["code"], "global_scope_unsupported",
            "{what}: {v}"
        );
        assert_eq!(
            v["error"]["message"],
            format!(
                "{flag} cannot be used with vendor: global installs have no project lockfile \
                 to wire vendored artifacts into"
            )
            .as_str(),
            "{what}: {v}"
        );
        assert_eq!(
            std::fs::read(root.join("package-lock.json")).unwrap(),
            original_lock,
            "{what}: the project's lockfile must stay"
        );
        assert!(
            !root.join(".socket/vendor").exists(),
            "{what}: nothing vendored into the project"
        );
        assert_eq!(
            std::fs::read(root.join(".socket/manifest.json")).unwrap(),
            manifest,
            "{what}: the manifest must stay"
        );
    }
    // The human path refuses the same way.
    assert_vendor_refused(root, &[], "wire vendored artifacts into", |what| {
        assert!(!root.join(".socket/vendor").exists(), "{what}");
    });
    // Control: without global scope the same project vendors.
    let (code, stdout, stderr) = common::run_with_env(
        root,
        &["vendor", "--json", "--silent", "--lock-timeout", "5"],
        &[("SOCKET_VENDOR_URL", &service.uri)],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert_ne!(
        std::fs::read(root.join("package-lock.json")).unwrap(),
        original_lock,
        "control: project vendor rewires the lock"
    );
}

/// `vendor --check -g` checks no project either: the project's vendored
/// state is not a global run's target.
#[test]
fn global_vendor_check_is_refused() {
    let project = vendored_project();
    assert_vendor_refused(
        project.root(),
        &["--check"],
        "check vendored artifacts in",
        |what| project.assert_untouched(what),
    );
}
