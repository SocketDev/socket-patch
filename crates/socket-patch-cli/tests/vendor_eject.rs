//! v5 WS2 eject: standalone `vendor` in a HOSTED project.
//!
//! A hosted project keeps no manifest and no ledger — its patch set is the
//! hosted pins in its lockfiles. A plain `vendor` there EJECTS: each pin's
//! record is fetched from the API (`patches/view/<uuid>`), vendored into
//! `.socket/vendor/`, and the lock is rewired hosted → vendored (restoring
//! the pin's upstream registry entry first, so `vendor --revert` later lands
//! on the upstream registry entry, not the hosted URL).
//!
//! Every run goes through the built binary with a scrubbed environment: the
//! API, the npm registry (`SOCKET_NPM_REGISTRY`) and the patch-server origin
//! (`SOCKET_PATCH_SERVER_URL`, what makes the mock hosted URL count as
//! hosted) all point at a wiremock; `SOCKET_VENDOR_SOURCE=build` keeps the
//! vendoring service out of it.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const GRANT: &str = "55555555-5555-4555-8555-555555555555";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";
const HOSTED_INTEGRITY: &str = "sha512-HOSTEDpatchedHOSTEDpatched==";
const UPSTREAM_INTEGRITY: &str = "sha512-UPSTREAMupstreamUPSTREAM==";

struct Project {
    tmp: tempfile::TempDir,
    server: MockServer,
}

impl Project {
    fn root(&self) -> &Path {
        self.tmp.path()
    }
    fn lock_path(&self) -> PathBuf {
        self.root().join("package-lock.json")
    }
    fn lock(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.lock_path()).unwrap()).unwrap()
    }
    fn lock_bytes(&self) -> Vec<u8> {
        std::fs::read(self.lock_path()).unwrap()
    }
    fn hosted_url(&self) -> String {
        format!(
            "{}/patch/npm/left-pad/1.3.0/{GRANT}/{UUID}/left-pad-1.3.0.tgz",
            self.server.uri()
        )
    }
    fn upstream_tarball(&self) -> String {
        format!("{}/left-pad/-/left-pad-1.3.0.tgz", self.server.uri())
    }
    fn artifact(&self) -> PathBuf {
        self.root()
            .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
    }
    fn redirect_state(&self) -> PathBuf {
        self.root().join(".socket/vendor/redirect-state.json")
    }

    /// Run the binary against the mocks with every ambient `SOCKET_*` var
    /// scrubbed.
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
        cmd.args(args)
            .arg("--cwd")
            .arg(self.root())
            .current_dir(self.root());
        for (key, _) in std::env::vars() {
            if key.starts_with("SOCKET_") {
                cmd.env_remove(key);
            }
        }
        let uri = self.server.uri();
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_API_URL", &uri)
            .env("SOCKET_API_TOKEN", "fake-token")
            .env("SOCKET_ORG_SLUG", ORG)
            .env("SOCKET_NPM_REGISTRY", &uri)
            .env("SOCKET_PATCH_SERVER_URL", &uri)
            .env("SOCKET_VENDOR_SOURCE", "build");
        let out = cmd.output().expect("spawn socket-patch");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn run_json(&self, args: &[&str]) -> (i32, Value) {
        let mut all = args.to_vec();
        all.push("--json");
        let (code, stdout, stderr) = self.run(&all);
        let env = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("--json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
        });
        (code, env)
    }
}

/// A hosted npm project: package-lock.json pins left-pad to the mock hosted
/// tarball (what `scan --mode hosted` leaves behind), the installed copy
/// carries the pristine file, and there is NO `.socket/` at all.
async fn hosted_project(hosted: bool) -> Project {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let project = Project { tmp, server };
    let root = project.root();
    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true,"dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();
    let (resolved, integrity) = if hosted {
        (project.hosted_url(), HOSTED_INTEGRITY.to_string())
    } else {
        (project.upstream_tarball(), UPSTREAM_INTEGRITY.to_string())
    };
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": { "name": "fixture", "version": "1.0.0", "dependencies": { "left-pad": "1.3.0" } },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": resolved,
                "integrity": integrity,
                "license": "WTFPL"
            }
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&lock).unwrap();
    bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), bytes).unwrap();
    project
}

/// The npm registry's version document for the upstream restore.
async fn mock_registry(p: &Project) {
    Mock::given(method("GET"))
        .and(path("/left-pad/1.3.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "left-pad",
            "version": "1.3.0",
            "dist": {
                "tarball": p.upstream_tarball(),
                "integrity": UPSTREAM_INTEGRITY,
                "shasum": "0000000000000000000000000000000000000000"
            }
        })))
        .mount(&p.server)
        .await;
}

/// `GET patches/view/<uuid>`: the record, with the patched blob inline.
async fn mock_view(p: &Project) {
    let before = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after = compute_git_sha256_from_bytes(PATCHED_INDEX);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before,
                    "afterHash": after,
                    "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED_INDEX)
                }
            },
            "vulnerabilities": {},
            "description": "eject fixture",
            "license": "MIT",
            "tier": "free"
        })))
        .mount(&p.server)
        .await;
}

fn find_event<'a>(env: &'a Value, action: &str, code: Option<&str>) -> &'a Value {
    env["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find(|e| e["action"] == action && code.is_none_or(|c| e["errorCode"] == c))
        })
        .unwrap_or_else(|| panic!("no `{action}` event (errorCode={code:?}) in:\n{env:#}"))
}

/// (1) + (2): eject vendors the hosted pin into `.socket/vendor/`, rewires
/// the lock to the vendored artifact, writes no hosted ledger and no
/// manifest; `vendor --revert` then returns the lock to the UPSTREAM
/// registry entry (registry tarball + upstream integrity), not the hosted
/// URL.
#[tokio::test]
async fn eject_vendors_hosted_pins_and_revert_returns_to_upstream() {
    let p = hosted_project(true).await;
    mock_registry(&p).await;
    mock_view(&p).await;

    let (code, env) = p.run_json(&["vendor"]);
    assert_eq!(code, 0, "eject must succeed: {env:#}");
    let applied = find_event(&env, "applied", None);
    assert_eq!(applied["purl"], PURL, "{env:#}");
    find_event(&env, "skipped", Some("vendor_takeover_reverted_redirect"));
    assert!(
        p.artifact().is_file(),
        "the artifact lands in .socket/vendor/"
    );
    let lock = p.lock();
    let entry = &lock["packages"]["node_modules/left-pad"];
    let resolved = entry["resolved"].as_str().unwrap_or_default();
    assert!(
        resolved.contains(&format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")),
        "the lock is wired to the vendored artifact: {lock:#}"
    );
    assert!(
        !String::from_utf8_lossy(&p.lock_bytes()).contains(&p.hosted_url()),
        "no hosted residue: {lock:#}"
    );
    assert!(!p.redirect_state().exists(), "no hosted ledger is written");
    assert!(
        !p.root().join(".socket/manifest.json").exists(),
        "an eject is manifest-free"
    );
    let state: Value =
        serde_json::from_slice(&std::fs::read(p.root().join(".socket/vendor/state.json")).unwrap())
            .unwrap();
    assert!(
        state["entries"].get(PURL).is_some(),
        "the vendor ledger tracks the ejected purl: {state:#}"
    );

    // A re-run is a no-op: nothing is hosted any more, so there is nothing
    // to eject (the no-manifest path), and the lock stays vendored.
    let vendored = p.lock_bytes();
    let (code, env) = p.run_json(&["vendor"]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["status"], "noManifest", "{env:#}");
    assert_eq!(p.lock_bytes(), vendored);

    let (code, env) = p.run_json(&["vendor", "--revert"]);
    assert_eq!(code, 0, "revert must succeed: {env:#}");
    let lock = p.lock();
    let entry = &lock["packages"]["node_modules/left-pad"];
    assert_eq!(
        entry["resolved"],
        p.upstream_tarball(),
        "revert lands on the upstream registry tarball: {lock:#}"
    );
    assert_eq!(entry["integrity"], UPSTREAM_INTEGRITY, "{lock:#}");
    assert!(!p.artifact().exists(), "the artifact is removed");
    assert!(!p.redirect_state().exists());
}

/// Human eject: the first line announces the eject.
#[tokio::test]
async fn eject_human_output_announces_the_eject() {
    let p = hosted_project(true).await;
    mock_registry(&p).await;
    mock_view(&p).await;

    let (code, stdout, stderr) = p.run(&["vendor", "--dry-run"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout
            .lines()
            .next()
            .is_some_and(|l| l.starts_with("Would eject 1 hosted package into .socket/vendor/")),
        "dry-run first line: {stdout}"
    );
    assert!(!p.artifact().exists(), "a dry run vendors nothing");

    let (code, stdout, stderr) = p.run(&["vendor"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout
            .lines()
            .next()
            .is_some_and(|l| l.starts_with("Ejecting 1 hosted package into .socket/vendor/")),
        "first line: {stdout}"
    );
    assert!(p.artifact().is_file());
}

/// (3): a failed view fetch is a `patch_fetch_failed` failure and exit 1;
/// the hosted pin is left exactly as found.
#[tokio::test]
async fn eject_view_fetch_failure_is_patch_fetch_failed() {
    let p = hosted_project(true).await;
    mock_registry(&p).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&p.server)
        .await;
    let before = p.lock_bytes();

    let (code, env) = p.run_json(&["vendor"]);
    assert_eq!(code, 1, "{env:#}");
    let failed = find_event(&env, "failed", Some("patch_fetch_failed"));
    assert_eq!(failed["purl"], PURL, "{env:#}");
    assert_eq!(p.lock_bytes(), before, "the hosted pin stays as found");
    assert!(!p.artifact().exists(), "nothing is vendored");
    assert!(!p.redirect_state().exists());
}

/// (4): no manifest and no hosted pins — the old calm no-op: exit 0,
/// `noManifest`, nothing written, no API call.
#[tokio::test]
async fn no_manifest_and_no_hosted_pins_is_a_noop() {
    let p = hosted_project(false).await;
    let before = p.lock_bytes();

    let (code, env) = p.run_json(&["vendor"]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["status"], "noManifest", "{env:#}");
    assert_eq!(p.lock_bytes(), before);
    assert!(!p.root().join(".socket").exists(), "nothing is created");
    assert!(
        p.server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the no-op never talks to the API or the registry"
    );

    let (code, stdout, stderr) = p.run(&["vendor"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("No manifest found, nothing to vendor."),
        "{stdout}"
    );
}
