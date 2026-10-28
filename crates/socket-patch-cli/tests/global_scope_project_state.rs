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
//!    the project vendors (#445, the reverse direction), except a NuGet
//!    project's own install in the global packages folder it restores into,
//!    which every global run leaves to the project's ledger (#489);
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
                v["error"]["message"]
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
        assert!(
            !v["events"]
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["details"]["mode"] == "hosted"),
            "{args:?}: {v}"
        );
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
    assert!(
        !v["events"]
            .as_array()
            .expect("events")
            .iter()
            .any(|e| e["details"]["mode"] == "vendored"),
        "{v}"
    );
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

// ═════════ 4b. a vendored NuGet project's global packages folder (#489) ═════════
//
// A PackageReference project restores into the global packages folder, so
// a global run's copy of a package the project vendors IS the project's
// installed copy: the restore extracted it from the vendored nupkg, and a
// locked restore never re-extracts it. The project's ledger still owns it
// under global scope; a global store the project does not restore into
// stays the global run's to patch.

const N_UUID: &str = "4f4f6b2c-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const N_PURL: &str = "pkg:nuget/Newtonsoft.Json@13.0.3";
const N_PRISTINE: &[u8] = b"The MIT License (MIT)\nCopyright (c) 2007 James Newton-King\n";
const N_PATCHED: &[u8] =
    b"The MIT License (MIT)\n// SOCKET-PATCH-MARKER\nCopyright (c) 2007 James Newton-King\n";

fn nupkg(license: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    let files: &[(&str, &[u8])] = &[
        ("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>"),
        ("_rels/.rels", b"<?xml version=\"1.0\"?><Relationships/>"),
        (
            "Newtonsoft.Json.nuspec",
            b"<?xml version=\"1.0\"?><package><metadata><id>Newtonsoft.Json</id>\
              <version>13.0.3</version></metadata></package>",
        ),
        ("lib/net6.0/Newtonsoft.Json.dll", b"MZ-fake-assembly"),
        ("LICENSE.md", license),
    ];
    for (name, bytes) in files {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

/// `Newtonsoft.Json` `13.0.3` extracted in global-packages-folder layout
/// under `store`, its `LICENSE.md` holding `license`.
fn write_newtonsoft(store: &Path, license: &[u8]) -> PathBuf {
    let dir = store.join("newtonsoft.json/13.0.3");
    std::fs::create_dir_all(dir.join("lib/net6.0")).unwrap();
    std::fs::write(dir.join("newtonsoft.json.13.0.3.nupkg"), nupkg(N_PRISTINE)).unwrap();
    std::fs::write(
        dir.join("newtonsoft.json.nuspec"),
        "<package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>",
    )
    .unwrap();
    std::fs::write(
        dir.join("lib/net6.0/Newtonsoft.Json.dll"),
        b"MZ-fake-assembly",
    )
    .unwrap();
    std::fs::write(dir.join("LICENSE.md"), license).unwrap();
    dir
}

/// A vendored NuGet project at `<tmp>/project` whose restore uses the
/// global packages folder `<tmp>/store` (`NUGET_PACKAGES`), after a locked
/// restore extracted the vendored nupkg there: the store copy is PATCHED.
struct VendoredNuget {
    tmp: tempfile::TempDir,
    ledger: Vec<u8>,
}

impl VendoredNuget {
    fn root(&self) -> PathBuf {
        self.tmp.path().join("project")
    }
    fn store(&self) -> PathBuf {
        self.tmp.path().join("store")
    }
    fn license(&self) -> Vec<u8> {
        std::fs::read(self.store().join("newtonsoft.json/13.0.3/LICENSE.md")).unwrap()
    }
    fn env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("SOCKET_PATCH_SERVER_URL", PATCH_HOST.to_string()),
            ("NUGET_PACKAGES", self.store().to_str().unwrap().to_string()),
        ]
    }
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let env = self.env();
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        common::run_with_env(&self.root(), args, &env)
    }
    fn assert_untouched(&self, what: &str) {
        assert_eq!(
            self.license(),
            N_PATCHED,
            "{what}: the project's installed copy in the global packages folder must stay patched"
        );
        assert_eq!(
            std::fs::read(self.root().join(".socket/vendor/state.json")).unwrap(),
            self.ledger,
            "{what}: the vendor ledger must stay byte-identical"
        );
    }
}

fn vendored_nuget() -> VendoredNuget {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("project");
    let store = tmp.path().join("store");
    write_newtonsoft(&store, N_PRISTINE);
    std::fs::create_dir_all(root.join("obj")).unwrap();
    std::fs::write(
        root.join("app.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>\
         <TargetFramework>net8.0</TargetFramework>\
         <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\
         </PropertyGroup><ItemGroup>\
         <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />\
         </ItemGroup></Project>\n",
    )
    .unwrap();
    let lock = json!({
        "version": 1,
        "dependencies": { "net8.0": { "Newtonsoft.Json": {
            "type": "Direct",
            "requested": "[13.0.3, )",
            "resolved": "13.0.3",
            "contentHash": "ORIGINALcachedhash=="
        }}}
    });
    std::fs::write(
        root.join("packages.lock.json"),
        serde_json::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();
    let assets = json!({
        "version": 3,
        "libraries": { "Newtonsoft.Json/13.0.3": { "type": "package", "path": "newtonsoft.json/13.0.3" } },
        "packageFolders": { format!("{}/", store.display()): {} },
    });
    std::fs::write(root.join("obj/project.assets.json"), assets.to_string()).unwrap();

    let after_hash = git_sha256(N_PATCHED);
    let manifest = json!({
        "patches": {
            N_PURL: {
                "uuid": N_UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { "LICENSE.md": {
                    "beforeHash": git_sha256(N_PRISTINE),
                    "afterHash": after_hash
                }},
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
    std::fs::write(socket.join("blobs").join(&after_hash), N_PATCHED).unwrap();
    std::fs::write(
        socket.join("blobs").join(git_sha256(N_PRISTINE)),
        N_PRISTINE,
    )
    .unwrap();

    let service = prebuilt_common::Server::project(&root);
    let (code, stdout, stderr) = common::run_with_env(
        &root,
        &["vendor", "--json", "--silent", "--lock-timeout", "5"],
        &[
            ("SOCKET_VENDOR_URL", &service.uri),
            ("NUGET_PACKAGES", store.to_str().unwrap()),
        ],
    );
    assert_eq!(
        code, 0,
        "fixture vendor: stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let ledger = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();
    assert!(
        String::from_utf8_lossy(&ledger).contains("pkg:nuget/"),
        "sanity: the ledger vendors Newtonsoft.Json: {}",
        String::from_utf8_lossy(&ledger)
    );
    // The locked restore extracts the vendored (patched) nupkg into the
    // global packages folder.
    std::fs::write(store.join("newtonsoft.json/13.0.3/LICENSE.md"), N_PATCHED).unwrap();
    VendoredNuget { tmp, ledger }
}

fn events_with(v: &Value, action: &str) -> Vec<Value> {
    v["events"]
        .as_array()
        .map(|e| {
            e.iter()
                .filter(|e| e["action"] == action)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// `rollback -g` from a vendored NuGet project leaves the project's
/// installed copy in the global packages folder patched (#489): restoring
/// it silently unpatched the project, since a locked restore never
/// re-extracts it.
#[test]
fn global_rollback_keeps_a_vendored_nuget_projects_install() {
    let project = vendored_nuget();
    for scope in [
        vec!["-g"],
        vec!["--global-prefix", project.store().to_str().unwrap()],
    ] {
        let mut args = vec!["rollback", "--json", "--yes", "--offline"];
        args.extend(scope.iter().copied());
        let (code, stdout, stderr) = project.run(&args);
        assert_eq!(code, 0, "{args:?}: stdout={stdout}\nstderr={stderr}");
        let v = parse(&stdout, &stderr);
        assert!(events_with(&v, "rolledBack").is_empty(), "{args:?}: {v}");
        project.assert_untouched(&format!("{args:?}"));
        assert!(
            serde_json::from_slice::<Value>(
                &std::fs::read(project.root().join(".socket/manifest.json")).unwrap()
            )
            .unwrap()["patches"]
                .get(N_PURL)
                .is_some(),
            "{args:?}: the project's vendored record must stay in the manifest"
        );
    }
}

/// `remove -g <purl>` leaves the project's install patched too (#489).
#[test]
fn global_remove_keeps_a_vendored_nuget_projects_install() {
    let project = vendored_nuget();
    let (code, stdout, stderr) =
        project.run(&["remove", N_PURL, "--json", "--yes", "--offline", "-g"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse(&stdout, &stderr);
    assert!(events_with(&v, "rolledBack").is_empty(), "{v}");
    project.assert_untouched("remove -g");
}

/// `apply -g` yields the project's install to its ledger (#489) instead of
/// taking it over as a global agent copy.
#[test]
fn global_apply_skips_a_vendored_nuget_projects_install() {
    let project = vendored_nuget();
    let (code, stdout, stderr) = project.run(&["apply", "--json", "--offline", "-g"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse(&stdout, &stderr);
    assert!(events_with(&v, "applied").is_empty(), "{v}");
    assert!(
        events_with(&v, "skipped")
            .iter()
            .any(|e| e["purl"] == N_PURL && e["errorCode"] == "vendored"),
        "the project's install is a vendored skip: {v}"
    );
    project.assert_untouched("apply -g");
}

/// `scan -g --mode agent` skips the project's install as
/// `vendored_ownership_retained` (#489) and records no agent patch for it.
#[tokio::test]
async fn global_agent_scan_skips_a_vendored_nuget_projects_install() {
    let project = vendored_nuget();
    // v5 vendored mode is manifest-free: nothing but the ledger marks the
    // copy as the project's.
    std::fs::write(
        project.root().join(".socket/manifest.json"),
        "{\n  \"patches\": {}\n}\n",
    )
    .unwrap();
    let mock = MockServer::start().await;
    mount_nuget_api(&mock).await;
    let uri = mock.uri();
    let (code, stdout, stderr) = project.run(&[
        "scan",
        "--json",
        "--yes",
        "--mode",
        "agent",
        "-g",
        "--api-url",
        &uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG,
    ]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse(&stdout, &stderr);
    let codes: Vec<&str> = v["warnings"]
        .as_array()
        .map(|w| w.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        codes.contains(&"vendored_ownership_retained"),
        "the project's ledger owns its install: {v}"
    );
    assert_eq!(
        std::fs::read_to_string(project.root().join(".socket/manifest.json")).unwrap(),
        "{\n  \"patches\": {}\n}\n",
        "no agent record for the project's install: {v}"
    );
    project.assert_untouched("scan -g --mode agent");
}

/// A global store the project does not restore into is still the global
/// run's (#446): `rollback --global-prefix <other>` restores its copy.
#[test]
fn global_rollback_restores_a_store_the_nuget_project_does_not_use() {
    let project = vendored_nuget();
    let other = empty_prefix();
    let copy = write_newtonsoft(other.path(), N_PATCHED);
    let (code, stdout, stderr) = project.run(&[
        "rollback",
        "--json",
        "--yes",
        "--offline",
        "--global-prefix",
        other.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert_eq!(
        std::fs::read(copy.join("LICENSE.md")).unwrap(),
        N_PRISTINE,
        "the unrelated global copy must be restored: {stdout}"
    );
    project.assert_untouched("rollback --global-prefix <other>");
}

async fn mount_nuget_api(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": N_PURL,
                "patches": [{
                    "uuid": N_UUID, "purl": N_PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": ["GHSA-newtonsoft-0"],
                    "severity": "high", "title": "Newtonsoft.Json",
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    let vulns = json!({
        "GHSA-newtonsoft-0": { "cves": [], "summary": "s", "severity": "high", "description": "d" }
    });
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.*(?i:newtonsoft\\.json)(%40|@)13\\.0\\.3$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [{
                "uuid": N_UUID, "purl": N_PURL, "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Newtonsoft.Json", "license": "MIT", "tier": "free",
                "vulnerabilities": vulns,
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    use base64::Engine;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{N_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": N_UUID, "purl": N_PURL, "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "LICENSE.md": {
                "beforeHash": git_sha256(N_PRISTINE),
                "afterHash": git_sha256(N_PATCHED),
                "blobContent": base64::engine::general_purpose::STANDARD.encode(N_PATCHED),
            }},
            "vulnerabilities": vulns,
            "description": "Newtonsoft.Json", "license": "MIT", "tier": "free",
        })))
        .mount(mock)
        .await;
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

// ═══════════════ 6. agent records patched in the other scope (#450) ═══════════════

/// `manifest_project` with its `node_modules/left-pad` copy holding `index`.
fn agent_project(index: &[u8]) -> tempfile::TempDir {
    let (tmp, _) = manifest_project();
    write_left_pad(&tmp.path().join("node_modules/left-pad"), index);
    tmp
}

fn manifest_of(root: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(root.join(".socket/manifest.json")).unwrap()).unwrap()
}

/// The record and both of its blobs are still on disk.
fn assert_record_kept(root: &Path, v: &Value, what: &str) {
    assert!(
        manifest_of(root)["patches"].get(V_PURL).is_some(),
        "{what}: the record of the copy patched in the other scope must stay; {v}"
    );
    for blob in [git_sha256(ORIG_INDEX), git_sha256(PATCHED_INDEX)] {
        assert!(
            root.join(".socket/blobs").join(&blob).is_file(),
            "{what}: blob {blob} must survive GC; {v}"
        );
    }
    let warning = v["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .find(|w| w["code"] == "patched_in_other_scope")
        .unwrap_or_else(|| panic!("{what}: expected a patched_in_other_scope warning; {v}"));
    assert!(
        warning["detail"].as_str().unwrap().contains(V_PURL),
        "{what}: the warning names the purl; {v}"
    );
}

/// Project apply, then `rollback --global-prefix` (#450, direction 1): the
/// global copy is already original, but the project's copy is still
/// patched, so the record and its blobs stay and the run says where the
/// patched copy is.
#[test]
fn global_rollback_keeps_a_record_patched_in_the_project() {
    let project = agent_project(PATCHED_INDEX);
    let root = project.path();
    let prefix = empty_prefix();
    write_left_pad(&prefix.path().join("left-pad"), ORIG_INDEX);
    for dry_run in [true, false] {
        let mut args = vec![
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--global-prefix",
            prefix.path().to_str().unwrap(),
        ];
        if dry_run {
            args.push("--dry-run");
        }
        let (code, stdout, stderr) = run(root, &args);
        assert_eq!(code, 0, "{args:?}: stdout={stdout}\nstderr={stderr}");
        let v = parse(&stdout, &stderr);
        assert_record_kept(root, &v, &format!("{args:?}"));
        assert!(
            !v["events"]
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["action"] == "removed"),
            "{args:?}: nothing leaves the manifest; {v}"
        );
    }
    assert_eq!(
        std::fs::read(root.join("node_modules/left-pad/index.js")).unwrap(),
        PATCHED_INDEX,
        "a global rollback leaves the project's copy alone"
    );

    // The rollback in the right scope then restores it and drops the record.
    let (code, stdout, stderr) = run(root, &["rollback", "--json", "--yes", "--offline"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert_eq!(
        std::fs::read(root.join("node_modules/left-pad/index.js")).unwrap(),
        ORIG_INDEX
    );
    assert!(
        manifest_of(root)["patches"].get(V_PURL).is_none(),
        "{stdout}"
    );
}

/// Every copy original in both scopes (the user reinstalled): rollback's
/// end state holds, so a global run still drops the record as before.
#[test]
fn global_rollback_drops_a_record_original_in_both_scopes() {
    let project = agent_project(ORIG_INDEX);
    let root = project.path();
    let prefix = empty_prefix();
    write_left_pad(&prefix.path().join("left-pad"), ORIG_INDEX);
    let (code, stdout, stderr) = run(
        root,
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
    assert!(manifest_of(root)["patches"].get(V_PURL).is_none(), "{v}");
    assert!(
        !v["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w["code"] == "patched_in_other_scope")),
        "{v}"
    );
}

/// A default global npm install at a temp root: a stub `npm` on `PATH`
/// answers `npm root -g` with it, holding a `left-pad` copy with `index`.
#[cfg(unix)]
struct StubGlobal {
    _tmp: tempfile::TempDir,
    bin: tempfile::TempDir,
    root: PathBuf,
}

#[cfg(unix)]
impl StubGlobal {
    fn new(index: &[u8]) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let tmp = empty_prefix();
        let root = tmp.path().join("lib/node_modules");
        write_left_pad(&root.join("left-pad"), index);
        let bin = tempfile::tempdir().unwrap();
        let npm = bin.path().join("npm");
        std::fs::write(&npm, format!("#!/bin/sh\necho '{}'\n", root.display())).unwrap();
        std::fs::set_permissions(&npm, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            _tmp: tmp,
            bin,
            root,
        }
    }
    fn path(&self) -> &str {
        self.bin.path().to_str().unwrap()
    }
}

/// `-g` apply, then a project `rollback` (#450, direction 2): the project's
/// copy is already original, but the default global install (here the
/// root a stub `npm root -g` prints) is still patched, so the record and
/// its blobs stay for `rollback -g`.
#[cfg(unix)]
#[test]
fn project_rollback_keeps_a_record_patched_globally() {
    let project = agent_project(ORIG_INDEX);
    let root = project.path();
    let global = StubGlobal::new(PATCHED_INDEX);
    let global_root = global.root.clone();
    let path = global.path();

    let (code, stdout, stderr) = common::run_with_env(
        root,
        &["rollback", "--json", "--yes", "--offline"],
        &[("SOCKET_PATCH_SERVER_URL", PATCH_HOST), ("PATH", path)],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse(&stdout, &stderr);
    assert_record_kept(root, &v, "project rollback");
    assert!(
        !v["events"]
            .as_array()
            .expect("events")
            .iter()
            .any(|e| e["action"] == "removed"),
        "nothing leaves the manifest; {v}"
    );
    assert_eq!(
        std::fs::read(global_root.join("left-pad/index.js")).unwrap(),
        PATCHED_INDEX,
        "a project rollback leaves the global copy alone"
    );

    // `rollback -g` restores the global copy and drops the record.
    let (code, stdout, stderr) = common::run_with_env(
        root,
        &["rollback", "-g", "--json", "--yes", "--offline"],
        &[("SOCKET_PATCH_SERVER_URL", PATCH_HOST), ("PATH", path)],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert_eq!(
        std::fs::read(global_root.join("left-pad/index.js")).unwrap(),
        ORIG_INDEX,
        "{stdout}"
    );
    assert!(
        manifest_of(root)["patches"].get(V_PURL).is_none(),
        "{stdout}"
    );
}

/// Project apply, then `rollback --global-prefix` over a global root with
/// no copy at all (#450, the common shape of direction 1): the purl is
/// not installed in this scope, but the project's copy is still patched,
/// so the record stays.
#[test]
fn global_rollback_keeps_a_record_not_installed_globally() {
    let project = agent_project(PATCHED_INDEX);
    let root = project.path();
    let prefix = empty_prefix();
    let (code, stdout, stderr) = run(
        root,
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
    assert_record_kept(root, &v, "rollback --global-prefix (not installed)");
    assert_eq!(
        std::fs::read(root.join("node_modules/left-pad/index.js")).unwrap(),
        PATCHED_INDEX
    );
}

/// The same manifest applied in both scopes: a project `rollback` restores
/// the project's copy, but the global copy is still patched, so the record
/// stays for `rollback -g` (#450), with a human warning naming it.
#[cfg(unix)]
#[test]
fn project_rollback_restoring_its_copy_keeps_a_record_patched_globally() {
    let project = agent_project(PATCHED_INDEX);
    let root = project.path();
    let global = StubGlobal::new(PATCHED_INDEX);
    let env = [
        ("SOCKET_PATCH_SERVER_URL", PATCH_HOST),
        ("PATH", global.path()),
    ];

    let (code, stdout, stderr) =
        common::run_with_env(root, &["rollback", "--json", "--yes", "--offline"], &env);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse(&stdout, &stderr);
    assert_record_kept(root, &v, "project rollback (both patched)");
    assert_eq!(
        std::fs::read(root.join("node_modules/left-pad/index.js")).unwrap(),
        ORIG_INDEX,
        "the project's copy is restored"
    );
    assert_eq!(
        std::fs::read(global.root.join("left-pad/index.js")).unwrap(),
        PATCHED_INDEX
    );

    // Human mode says where the patched copy is and how to restore it.
    write_left_pad(&root.join("node_modules/left-pad"), PATCHED_INDEX);
    let (code, stdout, stderr) =
        common::run_with_env(root, &["rollback", "--yes", "--offline"], &env);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains(&format!(
            "Warning: {V_PURL}: its copy in the global install ({}) is still patched or could \
             not be verified, so its manifest record was kept; run `socket-patch rollback \
             {V_PURL} -g` to restore it",
            global.root.join("left-pad").display()
        )),
        "{stderr}"
    );
    assert!(!stdout.contains("Removed"), "{stdout}");
}

/// A copy in the other scope whose patched file exists but cannot be
/// hashed (here a directory where `index.js` should be) may still be
/// patched, so the record stays rather than being stranded (#450).
#[test]
fn global_rollback_keeps_a_record_unverifiable_in_the_project() {
    let project = agent_project(ORIG_INDEX);
    let root = project.path();
    let index = root.join("node_modules/left-pad/index.js");
    std::fs::remove_file(&index).unwrap();
    std::fs::create_dir(&index).unwrap();
    let prefix = empty_prefix();
    write_left_pad(&prefix.path().join("left-pad"), ORIG_INDEX);
    let (code, stdout, stderr) = run(
        root,
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
    assert_record_kept(root, &v, "rollback --global-prefix (unverifiable)");
}
