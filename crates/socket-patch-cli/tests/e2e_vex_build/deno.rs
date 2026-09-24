//! Real-`deno` NEGATIVE capstone for manifest-less VEX: Deno has neither a
//! hosted rewriter nor a vendored backend, so nothing a Deno project commits
//! may ever be attested without the manifest — while agent-mode (manifest)
//! patches of the npm packages Deno installs keep working exactly as before.
//!
//! Per Deno major (1.x: `deno cache --node-modules-dir main.ts`; 2.x:
//! `deno install`), against the real npm registry:
//!
//! 1. the REAL install of `minimist@1.2.2` from a `package.json` writes
//!    `deno.lock` and `node_modules/.deno/minimist@1.2.2/…` (+ the
//!    `node_modules/minimist` link); `deno run` prints `PRISTINE`;
//! 2. HOSTED: `scan --mode hosted` with a stand-in API that GRANTS a hosted
//!    reference for that very package (on a configured `--patch-server-url`
//!    origin) must wire nothing — `package.json` + `deno.lock` byte-identical,
//!    no manifest — and a manifest-less `vex` has nothing to attest (exit 2,
//!    `manifest_not_found`) and makes ZERO patch-API requests, with and
//!    without `--no-verify`;
//! 3. VENDORED: `scan --mode vendored --vendor-source build` likewise
//!    commits no wiring Deno would consume, and `vex` again has nothing to
//!    attest;
//! 4. AGENT (manifest) mode, unchanged: a staged manifest + blob →
//!    `apply --vex` patches the installed file in place and attests it with
//!    the plain (no `(redirected)` / `(vendored)`) provenance; `deno run`
//!    now prints `PATCHED` (Deno consumes the patched bytes); the standalone
//!    `vex` with the manifest attests the same; with the manifest deleted it
//!    has nothing to attest (the lockfile names no patch).
//!
//! Gates mirror `e2e_nuget_dotnet_build.rs`: `#[ignore]` (network), a
//! missing `deno` SKIPs unless `SOCKET_PATCH_DENO_E2E_REQUIRED` is set
//! (non-empty), and `SOCKET_PATCH_DENO_E2E_VERSION` (`1`, `2`, `2.9` or an
//! exact release) must prefix `deno --version`. `SOCKET_PATCH_DENO` selects
//! the binary (a downloaded release zip for a local per-major loop).

use crate::vex_e2e_common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use vex_e2e_common::*;

const ORG: &str = "test-org";
const NAME: &str = "minimist";
const VERSION: &str = "1.2.2";
const PURL: &str = "pkg:npm/minimist@1.2.2";
const UUID: &str = "5d5d5d5d-1111-4111-8111-5d5d5d5d5d5d";
const PRODUCT: &str = "pkg:npm/deno-app@1.0.0";
const GHSA: &str = "GHSA-deno-vex-e2e0";
const CVE: &str = "CVE-2026-7320";
const FILE_KEY: &str = "package/index.js";
const PATCH_LINE: &[u8] = b"\nmodule.exports.__socketPatched = true;\n";
const MAIN_TS: &str = "import minimist from \"minimist\";\n\
    // deno-lint-ignore no-explicit-any\n\
    console.log((minimist as any).__socketPatched === true ? \"PATCHED\" : \"PRISTINE\");\n";

fn required() -> bool {
    std::env::var_os("SOCKET_PATCH_DENO_E2E_REQUIRED").is_some_and(|v| !v.is_empty())
}

struct Deno {
    bin: PathBuf,
    version: String,
    major: u32,
}

impl Deno {
    fn probe() -> Option<Self> {
        let bin = std::env::var_os("SOCKET_PATCH_DENO")
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from("deno"), PathBuf::from);
        let version = match Command::new(&bin).arg("--version").output() {
            // `deno 2.9.7 (stable, release, aarch64-apple-darwin)` …
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string(),
            _ => {
                assert!(
                    !required(),
                    "SOCKET_PATCH_DENO_E2E_REQUIRED is set but `{} --version` did not run",
                    bin.display()
                );
                println!("SKIP e2e_vex_build::deno: `deno` not installed");
                return None;
            }
        };
        if let Some(pin) = std::env::var("SOCKET_PATCH_DENO_E2E_VERSION")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
        {
            assert!(
                version == pin || version.starts_with(&format!("{pin}.")),
                "SOCKET_PATCH_DENO_E2E_VERSION pins deno {pin} but `deno --version` is {version}"
            );
        }
        let major = version
            .split('.')
            .next()
            .and_then(|m| m.parse().ok())
            .unwrap_or_else(|| panic!("unparsable deno version {version:?}"));
        println!("e2e_vex_build::deno: deno {version}");
        Some(Deno {
            bin,
            version,
            major,
        })
    }

    fn cmd(&self, cwd: &Path, deno_dir: &Path) -> Command {
        let mut cmd = Command::new(&self.bin);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("DENO_")
                || key.to_string_lossy().starts_with("NPM_CONFIG")
            {
                cmd.env_remove(key);
            }
        }
        cmd.current_dir(cwd)
            .env("DENO_DIR", deno_dir)
            .env("DENO_NO_UPDATE_CHECK", "1")
            .env("NO_COLOR", "1");
        cmd
    }

    fn ok(&self, out: Output, what: &str) -> String {
        assert!(
            out.status.success(),
            "deno {}: {what} failed\n--- stdout\n{}\n--- stderr\n{}",
            self.version,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// The era's install: 1.x resolves `package.json` deps into a local
    /// `node_modules/` through `deno cache --node-modules-dir`; 2.x through
    /// `deno install`.
    fn install(&self, cwd: &Path, deno_dir: &Path) {
        let mut cmd = self.cmd(cwd, deno_dir);
        if self.major < 2 {
            cmd.args(["cache", "--node-modules-dir", "main.ts"]);
        } else {
            cmd.arg("install");
        }
        self.ok(cmd.output().expect("spawn deno"), "install");
    }

    fn run_main(&self, cwd: &Path, deno_dir: &Path) -> String {
        let mut cmd = self.cmd(cwd, deno_dir);
        cmd.arg("run");
        if self.major < 2 {
            cmd.arg("--node-modules-dir");
        }
        cmd.args(["--allow-read", "--allow-env", "main.ts"]);
        self.ok(cmd.output().expect("spawn deno run"), "deno run main.ts")
    }
}

fn socket_patch(cwd: &Path, deno_dir: &Path, args: &[&str]) -> (Option<i32>, Value, String) {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    let out = cmd
        .args(args)
        .current_dir(cwd)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("DENO_DIR", deno_dir)
        .output()
        .expect("spawn socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?}: stdout is not JSON ({e})\n--- stdout\n{}\n--- stderr\n{stderr}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    (out.status.code(), env, stderr)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The authenticated API stand-in `scan` drives: batch → by-package →
/// reference GRANT (an npm hosted tarball on the stand-in's own origin) →
/// view with the inline patched blob.
struct Backend {
    server: wiremock::MockServer,
    rt: tokio::runtime::Runtime,
}

impl Backend {
    fn start(pristine: &[u8], patched: &[u8]) -> Self {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        let url = format!(
            "{}/patch/npm/{NAME}/{VERSION}/{HOSTED_TOKEN}/{UUID}/{NAME}-{VERSION}.tgz",
            server.uri()
        );
        let view = serde_json::json!({
            "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
            "files": { FILE_KEY: {
                "beforeHash": git_sha256(pristine),
                "afterHash": git_sha256(patched),
                "blobContent": b64(patched),
            } },
            "vulnerabilities": { GHSA: {
                "cves": [CVE], "summary": "s", "severity": "high", "description": "d"
            } },
            "description": "deno vex e2e", "license": "MIT", "tier": "free",
        });
        rt.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "packages": [{ "purl": PURL, "patches": [{
                        "uuid": UUID, "purl": PURL, "tier": "free", "cveIds": [CVE],
                        "ghsaIds": [GHSA], "severity": "high", "title": "t"
                    }] }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "^/v0/orgs/{ORG}/patches/by-package/.+$"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "patches": [{
                        "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
                        "description": "d", "license": "MIT", "tier": "free",
                        "vulnerabilities": view["vulnerabilities"].clone()
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "results": { UUID: {
                        "status": "granted", "url": url, "purl": PURL,
                        "artifacts": [{ "kind": "tarball", "url": url,
                            "integrity": { "sha512": "sha512-REVOT3BhdGNoZWREZW5vUGF0Y2hlZA==" } }],
                        "registryOverride": Value::Null,
                    } }
                })))
                .mount(&server)
                .await;
            for p in [
                format!("/v0/orgs/{ORG}/patches/view/{UUID}"),
                format!("/patch/view/{UUID}"),
            ] {
                Mock::given(method("GET"))
                    .and(path(p))
                    .respond_with(ResponseTemplate::new(200).set_body_json(view.clone()))
                    .mount(&server)
                    .await;
            }
        });
        Backend { server, rt }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    fn requests(&self) -> Vec<String> {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }
}

/// The project files Deno commits, byte-for-byte.
fn committed(project: &Path) -> Vec<(String, Vec<u8>)> {
    ["package.json", "deno.lock", "main.ts"]
        .iter()
        .map(|f| (f.to_string(), std::fs::read(project.join(f)).unwrap()))
        .collect()
}

/// No manifest, nothing wired: a manifest-less `vex` must have nothing to
/// attest and must not ask the patch API for anything.
fn assert_nothing_to_attest(project: &Path, deno_dir: &Path, patch_server: &str, what: &str) {
    assert!(
        !project.join(".socket/manifest.json").exists(),
        "{what}: no manifest may exist here"
    );
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(
            UUID,
            PURL,
            &[(FILE_KEY, &"b".repeat(64))],
            &[(GHSA, &[CVE])],
        ),
    )]);
    for no_verify in [false, true] {
        let mut run = VexRun::online(&api).env("DENO_DIR", deno_dir);
        run.product = Some(PRODUCT.to_string());
        run.patch_server_url = Some(patch_server.to_string());
        run.no_verify = no_verify;
        let out = run_vex(&binary(), project, &run);
        assert_eq!(out.code, Some(2), "{what} nv={no_verify}: {out}");
        assert_eq!(
            out.envelope["error"]["code"], "manifest_not_found",
            "{what}: {out}"
        );
        assert_absent(out.doc.as_ref(), PURL);
    }
    api.assert_no_requests();
}

#[test]
#[ignore = "real deno + npm registry: run with --ignored (CI e2e matrix pins deno 1.x and 2.x)"]
fn deno_hosted_and_vendored_never_attest_manifest_mode_unchanged() {
    let Some(deno) = Deno::probe() else {
        return;
    };
    let v = deno.version.clone();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let project = root.join("app");
    let deno_dir = root.join("deno-dir");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("package.json"),
        format!(
            "{{\n  \"name\": \"deno-app\",\n  \"version\": \"1.0.0\",\n  \
             \"dependencies\": {{ \"{NAME}\": \"{VERSION}\" }}\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(project.join("main.ts"), MAIN_TS).unwrap();

    // 1. The real install.
    deno.install(&project, &deno_dir);
    let installed = project.join(format!(
        "node_modules/.deno/{NAME}@{VERSION}/node_modules/{NAME}/index.js"
    ));
    let pristine = std::fs::read(&installed)
        .unwrap_or_else(|e| panic!("deno {v}: {} after install: {e}", installed.display()));
    assert!(
        project.join("deno.lock").is_file(),
        "deno {v} wrote deno.lock"
    );
    assert_eq!(deno.run_main(&project, &deno_dir), "PRISTINE");
    let mut patched = pristine.clone();
    patched.extend_from_slice(PATCH_LINE);
    let before = committed(&project);

    let backend = Backend::start(&pristine, &patched);
    let uri = backend.uri();
    let api_args = |mode: &str| -> Vec<String> {
        let mut a: Vec<String> = [
            "scan",
            "--json",
            "--yes",
            "--mode",
            mode,
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake-token",
            "--patch-server-url",
            &uri,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if mode == "vendored" {
            a.extend(["--vendor-source".to_string(), "build".to_string()]);
        }
        a
    };

    // 2. HOSTED: a granted reference for a Deno-installed package wires
    // nothing Deno reads.
    let args = api_args("hosted");
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, env, stderr) = socket_patch(&project, &deno_dir, &args);
    assert_eq!(
        code,
        Some(0),
        "deno {v}: scan --mode hosted: {env:#}\n{stderr}"
    );
    assert_eq!(env["redirect"]["redirected"], 0, "deno {v}: {env:#}");
    assert!(
        env["redirect"]["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w["code"] == "redirect_npm_no_lockfile")),
        "deno {v}: the npm rewriter found no npm lockfile to pin: {env:#}"
    );
    assert!(
        backend
            .requests()
            .iter()
            .any(|p| p.ends_with("/patches/batch")),
        "deno {v}: the scan really discovered the Deno-installed package"
    );
    assert_eq!(
        committed(&project),
        before,
        "deno {v}: hosted scan edited committed files"
    );
    assert_eq!(std::fs::read(&installed).unwrap(), pristine);
    assert_nothing_to_attest(&project, &deno_dir, &uri, &format!("deno {v} hosted"));
    let _ = std::fs::remove_dir_all(project.join(".socket"));

    // 3. VENDORED: nothing committed that Deno would consume either.
    let args = api_args("vendored");
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, env, stderr) = socket_patch(&project, &deno_dir, &args);
    assert_eq!(
        code,
        Some(1),
        "deno {v}: scan --mode vendored: {env:#}\n{stderr}"
    );
    assert!(
        env["vendor"]["events"].as_array().is_some_and(|e| e
            .iter()
            .any(|e| e["action"] == "failed" && e["errorCode"] == "vendor_lockfile_missing")),
        "deno {v}: vendoring refuses without an npm-family lockfile: {env:#}"
    );
    assert_eq!(
        committed(&project),
        before,
        "deno {v}: vendored scan edited committed files"
    );
    assert_eq!(std::fs::read(&installed).unwrap(), pristine);
    // The vendored scan's download phase left a manifest for the patch it
    // could not wire. Nothing applied it, so even WITH that manifest the
    // pristine installed tree attests nothing …
    assert!(project.join(".socket/manifest.json").is_file());
    let out = run_vex(
        &binary(),
        &project,
        &VexRun {
            product: Some(PRODUCT.to_string()),
            ..VexRun::offline()
        }
        .env("DENO_DIR", &deno_dir),
    );
    assert_eq!(
        out.code,
        Some(1),
        "deno {v}: unapplied manifest patch: {out}"
    );
    assert_absent(out.doc.as_ref(), PURL);
    // … and without it there is nothing to attest at all.
    strip_manifest(&project);
    assert_nothing_to_attest(&project, &deno_dir, &uri, &format!("deno {v} vendored"));
    let _ = std::fs::remove_dir_all(project.join(".socket"));
    assert_eq!(deno.run_main(&project, &deno_dir), "PRISTINE");

    // 4. AGENT mode, as before: manifest + blob → apply --vex patches the
    // installed file (through Deno's node_modules layout) and attests it.
    let socket = project.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(&patched)), &patched).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "patches": { PURL: {
                "uuid": UUID, "exportedAt": "2026-01-01T00:00:00Z",
                "files": { FILE_KEY: {
                    "beforeHash": git_sha256(&pristine), "afterHash": git_sha256(&patched)
                } },
                "vulnerabilities": { GHSA: {
                    "cves": [CVE], "summary": "s", "severity": "high", "description": "d"
                } },
                "description": "deno agent-mode patch", "license": "MIT", "tier": "free",
            } },
            // Deno projects run no npm install hook: declare the ecosystem
            // manual so agent-mode statements are emitted (property 7).
            "setup": { "manual": ["npm"] },
        }))
        .unwrap(),
    )
    .unwrap();
    let quiet = PatchApi::empty();
    let apply = VexRun {
        proxy_url: Some(quiet.uri()),
        offline: true,
        product: Some(PRODUCT.to_string()),
        ..VexRun::default()
    }
    .via(VexVia::Apply)
    .env("DENO_DIR", &deno_dir);
    let out = run_vex(&binary(), &project, &apply);
    assert_eq!(out.code, Some(0), "deno {v}: apply --vex: {out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Applied, &[(GHSA, &[CVE])]);
    assert_eq!(
        std::fs::read(&installed).unwrap(),
        patched,
        "deno {v}: patched in place"
    );
    assert_eq!(
        deno.run_main(&project, &deno_dir),
        "PATCHED",
        "deno {v} consumes the patched bytes"
    );
    let standalone = VexRun {
        product: Some(PRODUCT.to_string()),
        ..VexRun::offline()
    }
    .env("DENO_DIR", &deno_dir);
    let out = run_vex(&binary(), &project, &standalone);
    assert_eq!(out.code, Some(0), "deno {v}: vex with the manifest: {out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Applied, &[(GHSA, &[CVE])]);
    assert_eq!(
        committed(&project),
        before,
        "agent mode never edits the lockfile"
    );

    strip_manifest(&project);
    let out = run_vex(&binary(), &project, &standalone);
    assert_eq!(
        out.code,
        Some(2),
        "deno {v}: agent patch without the manifest: {out}"
    );
    assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
    quiet.assert_no_requests();
}
