//! Vendoring a gem the Bundler lock names as precompiled platform gems:
//! one tree per locked platform, each from that platform's own patch, and
//! what a run says of it (one event per platform gem, one package).
//!
//! The patch service is a stand-in that answers in the shape of the wire
//! contract: the gem patch's reference lists every platform gem of the
//! version (`registryOverride.identifiers.gemBuilds`) with the patch of
//! each patched build, and each such patch serves that platform's gem
//! (`tarball`) and stub gemspec. No Bundler runs here.

use crate::common::envelope::find_event;
use crate::common::{binary, git_sha256, hermetic, sha256_hex};

use std::path::Path;

use base64::Engine as _;
use sha2::{Digest, Sha512};
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A name nothing on the developer's machine can have installed.
const NAME: &str = "sockplatgem";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:gem/sockplatgem@1.0.0";
/// The gem's patch: the patch of its ruby gem.
const UUID: &str = "5eed0000-0000-4000-8000-000000000001";
/// A later patch of the gem.
const UUID_B: &str = "5eed0000-0000-4000-8000-000000000002";
const DARWIN: &str = "arm64-darwin";
const LINUX: &str = "x86_64-linux-gnu";
const DARWIN_UUID: &str = "5eed0000-0000-4000-8000-0000000000da";
const LINUX_UUID: &str = "5eed0000-0000-4000-8000-0000000000f1";
const LIB: &str = "lib/sockplatgem.rb";
const SO: &str = "lib/sockplatgem/ext.so";
const PRISTINE: &[u8] = b"module SockPlatGem; VERSION = '1.0.0'; end\n";
const PATCHED: &[u8] = b"module SockPlatGem; VERSION = '1.0.0'; SAFE = true; end\n";
const GHSA: &str = "GHSA-plat-form-gems";
const CVE: &str = "CVE-2026-31337";
const ORG: &str = "test-org";

const GEMFILE: &str = "source \"https://rubygems.org\"\n\ngem \"sockplatgem\", \"~> 1.0\"\n";

/// Bundler's lock of a project that takes the gem as precompiled platform
/// gems (no `CHECKSUMS`: a bundler 2.5 lock).
fn lock() -> String {
    format!(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    {NAME} ({VERSION}-{DARWIN})\n    \
         {NAME} ({VERSION}-{LINUX})\n\nPLATFORMS\n  {DARWIN}\n  {LINUX}\n\nDEPENDENCIES\n  \
         {NAME} (~> 1.0)\n\nBUNDLED WITH\n   2.5.22\n"
    )
}

/// A minimal `.gem`: an uncompressed tar whose `data.tar.gz` holds `files`.
fn make_gem(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut data = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        data.append_data(&mut header, path, *bytes).unwrap();
    }
    let data_tar = data.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &data_tar).unwrap();
    let data_tar_gz = gz.finish().unwrap();
    let mut gem = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(data_tar_gz.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    gem.append_data(&mut header, "data.tar.gz", data_tar_gz.as_slice())
        .unwrap();
    gem.into_inner().unwrap()
}

/// The patched gem of `platform`: the patched Ruby file and the platform's
/// own binary.
fn platform_gem(platform: &str) -> Vec<u8> {
    make_gem(&[(LIB, PATCHED), (SO, platform.as_bytes())])
}

fn stub(platform: &str) -> Vec<u8> {
    format!(
        "Gem::Specification.new do |s|\n  s.name = \"{NAME}\"\n  s.version = \"{VERSION}\"\n  \
         s.platform = \"{platform}\"\n  s.summary = \"a synthetic fixture gem\"\n  \
         s.authors = [\"Socket\"]\n  s.require_paths = [\"lib\"]\nend\n"
    )
    .into_bytes()
}

fn sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

fn build_uuid(platform: &str) -> &'static str {
    match platform {
        DARWIN => DARWIN_UUID,
        _ => LINUX_UUID,
    }
}

/// The gem patch's record as the patch API's view serves it.
fn patch_view() -> serde_json::Value {
    patch_view_of(UUID)
}

/// [`patch_view`] for the gem patch `uuid`.
fn patch_view_of(uuid: &str) -> serde_json::Value {
    serde_json::json!({
        "uuid": uuid,
        "purl": format!("{PURL}?platform=ruby"),
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": {
            LIB: {
                "beforeHash": git_sha256(PRISTINE),
                "afterHash": git_sha256(PATCHED),
                "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED),
            }
        },
        "vulnerabilities": {
            GHSA: {
                "cves": [CVE],
                "summary": "a synthetic vulnerability",
                "severity": "high",
                "description": "details"
            }
        },
        "description": "synthetic platform gem vendor test patch",
        "license": "MIT",
        "tier": "free"
    })
}

/// A patch service where the platforms of `patched` have a patched build
/// and those of `pass_through` are listed as upstream's own gem.
async fn service(patched: &[&'static str], pass_through: &[&'static str]) -> MockServer {
    let granted: Vec<(&'static str, Option<&'static str>)> =
        patched.iter().map(|platform| (*platform, None)).collect();
    service_of(UUID, &granted, pass_through).await
}

/// [`service`] for the gem patch `uuid`, where the reference of the patch
/// of each patched build answers the status named beside its platform
/// (which is no grant), or a grant when none is named.
async fn service_of(
    uuid: &'static str,
    patched: &[(&'static str, Option<&'static str>)],
    pass_through: &[&'static str],
) -> MockServer {
    // Hand the test's task back to the runtime once, which renews its tokio
    // cooperative budget. A `MockServer` verifies its mocks when it is
    // dropped, on a blocking executor of its own, and a task that has used
    // up its budget never gets through that. Every mount, every read of
    // the received requests and every server start spends some of it, and
    // a test that only runs child processes in between never yields by
    // itself.
    tokio::task::yield_now().await;
    let server = MockServer::start().await;
    let mut results = serde_json::Map::new();
    let mut gem_builds = Vec::new();
    for (platform, status) in patched {
        let own = build_uuid(platform);
        let (gem, gemspec) = (platform_gem(platform), stub(platform));
        gem_builds.push(serde_json::json!({
            "platform": platform, "gemChecksumSha256": sha256_hex(&gem), "patchUuid": own
        }));
        if let Some(status) = status {
            let unserved = serde_json::json!({ "status": status, "url": null, "artifacts": [] });
            results.insert(own.to_string(), unserved);
            continue;
        }
        let base = format!("/patch/gem/{NAME}/{VERSION}/tok/{own}/{NAME}-{VERSION}-{platform}");
        let mut artifacts = Vec::new();
        for (kind, ext, bytes) in [
            ("tarball", "gem", &gem),
            ("gem-stub-gemspec", "gemspec", &gemspec),
        ] {
            let route = format!("{base}.{ext}");
            artifacts.push(serde_json::json!({
                "kind": kind,
                "url": format!("{}{route}", server.uri()),
                "integrity": { "sha512": sri(bytes) }
            }));
            Mock::given(method("GET"))
                .and(wm_path(route))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
                .mount(&server)
                .await;
        }
        results.insert(
            own.to_string(),
            serde_json::json!({
                "status": "granted",
                "purl": format!("{PURL}?platform={platform}"),
                "artifacts": artifacts
            }),
        );
    }
    for platform in pass_through {
        gem_builds.push(serde_json::json!({
            "platform": platform, "gemChecksumSha256": "ab".repeat(32), "patchUuid": null
        }));
    }
    gem_builds.sort_by_key(|build| build["platform"].as_str().map(str::to_string));
    let ruby_gem = make_gem(&[(LIB, PATCHED)]);
    let ruby_url = format!(
        "{}/patch/gem/{NAME}/{VERSION}/tok/{uuid}/{NAME}-{VERSION}.gem",
        server.uri()
    );
    results.insert(
        uuid.to_string(),
        serde_json::json!({
            "status": "granted",
            "purl": format!("{PURL}?platform=ruby"),
            "url": ruby_url,
            "artifacts": [{ "kind": "tarball", "url": ruby_url,
                            "integrity": { "sha512": sri(&ruby_gem) } }],
            "registryOverride": {
                "kind": "rubygems-compact-index",
                "indexUrl": format!("{}/patch-registry/gem/tok/{uuid}/s/4", server.uri()),
                "identifiers": {
                    "name": NAME, "version": VERSION,
                    "gemChecksumSha256": sha256_hex(&ruby_gem),
                    "gemBuilds": gem_builds
                }
            }
        }),
    );
    Mock::given(method("POST"))
        .and(wm_path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(move |request: &wiremock::Request| {
            let asked: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or_default();
            let answered: serde_json::Map<String, serde_json::Value> = asked["uuids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|uuid| {
                    let uuid = uuid.as_str()?;
                    Some((uuid.to_string(), results.get(uuid)?.clone()))
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": answered }))
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(wm_path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(patch_view_of(uuid)))
        .mount(&server)
        .await;
    server
}

/// The uuids each package reference request named, in arrival order.
async fn reference_requests(server: &MockServer) -> Vec<Vec<String>> {
    let requests = server.received_requests().await.unwrap_or_default();
    requests
        .iter()
        .filter(|request| request.url.path().ends_with("/patches/package"))
        .map(|request| {
            let asked: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or_default();
            let uuids = asked["uuids"].as_array().into_iter().flatten();
            uuids
                .filter_map(|uuid| Some(uuid.as_str()?.to_string()))
                .collect()
        })
        .collect()
}

/// The paths of the artifacts downloaded from `server`.
async fn downloads(server: &MockServer) -> Vec<String> {
    let requests = server.received_requests().await.unwrap_or_default();
    let mut paths: Vec<String> = requests
        .iter()
        .map(|request| request.url.path().to_string())
        .filter(|path| path.starts_with("/patch/gem/"))
        .collect();
    paths.sort();
    paths
}

/// A Bundler project locking the gem as platform gems, with the manifest
/// record of the gem's patch and its staged after-blob.
fn write_project(root: &Path) {
    std::fs::write(root.join("Gemfile"), GEMFILE).unwrap();
    std::fs::write(root.join("Gemfile.lock"), lock()).unwrap();
    write_manifest(root, UUID);
}

/// The manifest record of the gem patch `uuid`, with its staged
/// after-blob.
fn write_manifest(root: &Path, uuid: &str) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let view = patch_view();
    let manifest = serde_json::json!({
        "patches": {
            PURL: {
                "uuid": uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    LIB: {
                        "beforeHash": git_sha256(PRISTINE),
                        "afterHash": git_sha256(PATCHED),
                    }
                },
                "vulnerabilities": view["vulnerabilities"],
                "description": view["description"],
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(PATCHED)), PATCHED).unwrap();
}

/// `socket-patch <args>` at `root` against the stand-in service, hermetic
/// (no ambient `SOCKET_*`, `BUNDLE_*` or gem home).
fn run(root: &Path, args: &[&str], api: &str) -> (i32, String, String) {
    let mut cmd = hermetic::command(&binary());
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Bundle]);
    cmd.env_remove("GEM_HOME").env_remove("GEM_PATH");
    crate::common::jvm_env::isolate_cli(&mut cmd);
    cmd.args(args)
        .args([
            "--api-url",
            api,
            "--proxy-url",
            api,
            "--api-token",
            "fake-token",
            "--org",
            ORG,
        ])
        .current_dir(root);
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_json(root: &Path, args: &[&str], api: &str) -> (i32, serde_json::Value, String) {
    let (code, stdout, stderr) = run(root, args, api);
    let env: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{args:?} must emit JSON: {e}\n{stdout}\n{stderr}"));
    (code, env, stderr)
}

const VENDOR: &[&str] = &["vendor", "--json", "--vendor-source", "service"];

/// The counted events of `env` with `action`, as `(purl, uuid, gemFix,
/// platform, errorCode)`.
fn gem_events<'a>(
    env: &'a serde_json::Value,
    action: &str,
) -> Vec<(&'a str, &'a str, &'a str, &'a str, &'a str)> {
    let text = |value: &'a serde_json::Value| value.as_str().unwrap_or_default();
    crate::common::envelope::events(env)
        .iter()
        .filter(|event| event["action"] == action)
        .map(|event| {
            (
                text(&event["purl"]),
                text(&event["uuid"]),
                text(&event["details"]["gemFix"]),
                text(&event["details"]["platform"]),
                text(&event["errorCode"]),
            )
        })
        .collect()
}

/// One event per platform gem, in lock order, each under its own patch.
fn per_platform_gem(
    code: &'static str,
) -> Vec<(
    String,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
)> {
    [DARWIN, LINUX]
        .into_iter()
        .map(|platform| {
            (
                format!("{PURL}?platform={platform}"),
                build_uuid(platform),
                UUID,
                platform,
                code,
            )
        })
        .collect()
}

fn assert_per_platform_gem(env: &serde_json::Value, action: &str, code: &'static str) {
    let got = gem_events(env, action);
    let got: Vec<(&str, &str, &str, &str, &str)> = got
        .into_iter()
        .filter(|event| !event.2.is_empty())
        .collect();
    let want = per_platform_gem(code);
    let want: Vec<(&str, &str, &str, &str, &str)> = want
        .iter()
        .map(|(purl, uuid, fix, platform, code)| (purl.as_str(), *uuid, *fix, *platform, *code))
        .collect();
    assert_eq!(got, want, "`{action}` events per platform gem: {env:#}");
}

fn tree(root: &Path, platform: &str) -> std::path::PathBuf {
    root.join(format!(
        ".socket/vendor/gem/{UUID}/{NAME}-{VERSION}/{platform}"
    ))
}

fn ledger(root: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Every locked platform has a patched build: one tree per platform from
/// that platform's own patch (one reference request for the gem's patch,
/// one for both platform patches together), the ledger records each tree's
/// patch and digests, and every run reports the gem as one package with
/// one counted event per platform gem: `applied`, then `already_vendored`
/// on a re-run, `verified` / `failed` under `--check`, and after a tree is
/// damaged a rebuild from the recorded patches alone. `vex` attests each
/// platform gem under its own patch, offline. `--revert` undoes it all.
#[tokio::test]
async fn a_platform_locked_gem_vendors_and_reports_per_platform_gem() {
    let server = service(&[DARWIN, LINUX], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root);

    // 1. Vendor.
    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 2, "{env:#}");
    assert_eq!(env["summary"]["failed"], 0, "{env:#}");
    assert_per_platform_gem(&env, "applied", "");
    for platform in [DARWIN, LINUX] {
        assert_eq!(
            std::fs::read(tree(root, platform).join(LIB)).unwrap(),
            PATCHED
        );
        assert_eq!(
            std::fs::read(tree(root, platform).join(SO)).unwrap(),
            platform.as_bytes()
        );
        assert!(tree(root, platform)
            .join(format!("{NAME}.gemspec"))
            .is_file());
    }
    assert_eq!(
        reference_requests(&server).await,
        [
            vec![UUID.to_string()],
            vec![DARWIN_UUID.to_string(), LINUX_UUID.to_string()],
        ],
        "the gem patch's reference, then ONE request for the platform patches"
    );
    assert_eq!(
        downloads(&server).await.len(),
        4,
        "a gem and a stub per platform"
    );
    let lock_wired = std::fs::read_to_string(root.join("Gemfile.lock")).unwrap();
    assert!(
        lock_wired.starts_with(&format!(
            "PATH\n  remote: .socket/vendor/gem/{UUID}/{NAME}-{VERSION}\n  specs:\n    {NAME} \
             ({VERSION}-{DARWIN})\n    {NAME} ({VERSION}-{LINUX})\n"
        )),
        "{lock_wired}"
    );
    let state = ledger(root);
    let entry = &state["entries"][PURL];
    assert_eq!(entry["uuid"], UUID);
    assert_eq!(
        entry["gemBuilds"],
        serde_json::json!([
            { "platform": DARWIN, "uuid": DARWIN_UUID,
              "gemIntegrity": sri(&platform_gem(DARWIN)), "gemspecIntegrity": sri(&stub(DARWIN)) },
            { "platform": LINUX, "uuid": LINUX_UUID,
              "gemIntegrity": sri(&platform_gem(LINUX)), "gemspecIntegrity": sri(&stub(LINUX)) }
        ])
    );

    // 2. An in-sync re-run: one package, one event per platform gem, and
    //    nothing asked of the service.
    let asked = server.received_requests().await.unwrap().len();
    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["skipped"], 2, "{env:#}");
    assert_eq!(env["summary"]["applied"], 0, "{env:#}");
    assert_per_platform_gem(&env, "skipped", "already_vendored");
    let (code, stdout, stderr) = run(
        root,
        &["vendor", "--vendor-source", "service"],
        &server.uri(),
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 package is already vendored; nothing to do."),
        "the gem is one package:\n{stdout}\n{stderr}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), asked);

    // 3. `vendor --check`: one verdict per platform gem.
    let (code, env, stderr) = run_json(root, &["vendor", "--check", "--json"], &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["verified"], 2, "{env:#}");
    assert_per_platform_gem(&env, "verified", "vendor_check_ok");

    // 4. `vex`, offline: each platform gem under its own patch, with the
    //    vulnerabilities of the gem patch's record; the gem's own patch is
    //    not what any statement names.
    let out = root.join("vex.json");
    let (code, stdout, stderr) = run(
        root,
        &[
            "vex",
            "--json",
            "--offline",
            "--product",
            "pkg:gem/app@1.0.0",
            "--output",
            out.to_str().unwrap(),
        ],
        &server.uri(),
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let statements = doc["statements"].as_array().expect("statements");
    assert_eq!(statements.len(), 1, "one vulnerability: {doc:#}");
    let statement = &statements[0];
    assert_eq!(statement["vulnerability"]["name"], GHSA);
    assert_eq!(statement["status"], "not_affected");
    let attested: Vec<&str> = statement["products"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|product| product["subcomponents"].as_array().into_iter().flatten())
        .filter_map(|component| component["@id"].as_str())
        .collect();
    for platform in [DARWIN, LINUX] {
        let purl = format!("{PURL}?platform={platform}");
        assert!(
            attested.contains(&purl.as_str()),
            "{platform}: {attested:?}"
        );
    }
    assert!(
        !attested.contains(&format!("{PURL}?platform=ruby").as_str()),
        "{attested:?}"
    );
    let impact = statement["impact_statement"].as_str().unwrap_or_default();
    for own in [DARWIN_UUID, LINUX_UUID] {
        let part = format!("Patched via Socket patch {own} (vendored)");
        assert!(impact.split("; ").any(|p| p == part), "{impact}");
    }
    assert!(!impact.contains(UUID), "{impact}");
    // The run's events name the gem's patch as the fix of each platform gem.
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("the vex envelope");
    let fixes: Vec<(&str, &str, &str)> = envelope["events"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|event| {
            let details = &event["details"];
            (
                event["action"].as_str().unwrap_or_default(),
                details["platform"].as_str().unwrap_or_default(),
                details["gemFix"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        fixes,
        [("verified", DARWIN, UUID), ("verified", LINUX, UUID)],
        "{envelope:#}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        asked,
        "offline"
    );

    // 5. A damaged tree: the check fails per platform gem, and the next
    //    run rebuilds the copy from the patches the ledger records, asked
    //    for in one request (the gem patch's reference is not needed).
    std::fs::write(tree(root, LINUX).join(SO), b"another binary").unwrap();
    let (code, env, stderr) = run_json(root, &["vendor", "--check", "--json"], &server.uri());
    assert_eq!(code, 1, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["failed"], 2, "{env:#}");
    assert_per_platform_gem(&env, "failed", "vendor_check_failed");
    let before = reference_requests(&server).await.len();
    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["rebuilt"], 1, "{env:#}");
    assert_per_platform_gem(&env, "skipped", "already_vendored");
    assert_eq!(
        reference_requests(&server).await[before..],
        [vec![DARWIN_UUID.to_string(), LINUX_UUID.to_string()]]
    );
    assert_eq!(
        std::fs::read(tree(root, LINUX).join(SO)).unwrap(),
        LINUX.as_bytes()
    );
    let (code, env, stderr) = run_json(root, &["vendor", "--check", "--json"], &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");

    // 6. Revert.
    let (code, env, stderr) = run_json(root, &["vendor", "--revert", "--json"], &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile")).unwrap(),
        GEMFILE
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile.lock")).unwrap(),
        lock()
    );
    assert!(!root.join(".socket/vendor").exists());
}

/// A locked platform with no patched build: the gem is not vendored, the
/// run exits 0 with nothing written and nothing downloaded, and says so in
/// one plain line (a counted benign skip in `--json`).
#[tokio::test]
async fn a_locked_platform_without_a_patched_build_is_one_line_and_no_failure() {
    let server = service(&[LINUX], &[DARWIN]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root);
    let line = format!(
        "{NAME}@{VERSION} is not vendored: no patched build yet for {DARWIN} ({LINUX} has one). \
         Vendored mode needs every locked platform; `scan --mode hosted` can patch the others now."
    );

    let (code, stdout, stderr) = run(
        root,
        &["vendor", "--vendor-source", "service"],
        &server.uri(),
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    // All of stderr but the note about this test's stand-in API token.
    let said: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("--api-token") && !l.contains("fake-token"))
        .collect();
    assert_eq!(said, [line.as_str()], "one line, no warning:\n{stderr}");
    assert!(
        stdout.contains("Vendored 0 packages; 1 skipped."),
        "{stdout}"
    );

    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(env["summary"]["applied"], 0, "{env:#}");
    assert_eq!(env["summary"]["failed"], 0, "{env:#}");
    assert_eq!(env["summary"]["skipped"], 1, "{env:#}");
    let skipped = gem_events(&env, "skipped");
    assert_eq!(
        skipped,
        [(PURL, "", "", "", "vendor_prebuilt_platform_pending")],
        "{env:#}"
    );
    assert_eq!(env["events"][0]["reason"], line.as_str());

    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile")).unwrap(),
        GEMFILE
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile.lock")).unwrap(),
        lock()
    );
    assert!(!root.join(".socket/vendor").exists(), "nothing is written");
    assert_eq!(downloads(&server).await, Vec::<String>::new());
    assert_eq!(
        reference_requests(&server).await,
        [vec![UUID.to_string()], vec![UUID.to_string()]],
        "each run asks for the gem patch's reference and nothing else"
    );
}

/// Ledger entries a development build wrote still read. An entry whose
/// `gemBuilds` items carry fields this build does not know checks as if
/// they were not there. An entry that has the key `gemPlatforms` in place
/// of `gemBuilds` (the platforms of its copy, with no patch named for
/// their trees) reads with the key ignored: a run says of it what it says
/// of the same ledger without the key. `vendor --revert` and `rollback`
/// need nothing the key held: each restores the Gemfile and the lock byte
/// for byte from the originals the entry records, and removes the copy.
#[tokio::test]
async fn ledger_entries_of_development_builds_still_read_and_revert() {
    let server = service(&[DARWIN, LINUX], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = &tmp.path().join("project");
    std::fs::create_dir(root).unwrap();
    write_project(root);
    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    let state_path = root.join(".socket/vendor/state.json");
    let current = ledger(root);
    let check = |state: &serde_json::Value| {
        std::fs::write(&state_path, serde_json::to_vec_pretty(state).unwrap()).unwrap();
        run_json(root, &["vendor", "--check", "--json"], &server.uri())
    };

    // Items with unknown fields.
    let mut extended = current.clone();
    for item in extended["entries"][PURL]["gemBuilds"]
        .as_array_mut()
        .unwrap()
    {
        let item = item.as_object_mut().unwrap();
        item.insert("rebuiltFromUuid".into(), serde_json::json!(UUID));
        item.insert(
            "record".into(),
            serde_json::json!({ "uuid": UUID, "files": {} }),
        );
    }
    let (code, env, stderr) = check(&extended);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_per_platform_gem(&env, "verified", "vendor_check_ok");

    // The key `gemPlatforms` in place of `gemBuilds`: the ledger reads,
    // and the run is the one over the ledger without the key.
    let mut without_key = current.clone();
    let entry = without_key["entries"][PURL].as_object_mut().unwrap();
    assert!(entry.remove("gemBuilds").is_some());
    let mut with_key = without_key.clone();
    let entry = with_key["entries"][PURL].as_object_mut().unwrap();
    entry.insert("gemPlatforms".into(), serde_json::json!([DARWIN, LINUX]));
    let (plain_code, plain, _) = check(&without_key);
    let (code, env, stderr) = check(&with_key);
    assert!(
        env["error"].is_null(),
        "the ledger reads: {env:#}\n{stderr}"
    );
    assert_eq!((code, &env), (plain_code, &plain), "the key is ignored");

    // Each way to unvendor the gem, over that ledger.
    let unvendor: [&[&str]; 2] = [&["vendor", "--revert", "--json"], &["rollback", "--json"]];
    for command in unvendor {
        let copy = tmp.path().join(command[0]);
        crate::common::fs_tree::copy_tree(root, &copy);
        let (code, env, stderr) = run_json(&copy, command, &server.uri());
        assert_eq!(code, 0, "{command:?}\n{env:#}\n{stderr}");
        assert_eq!(
            std::fs::read_to_string(copy.join("Gemfile")).unwrap(),
            GEMFILE,
            "{command:?}"
        );
        assert_eq!(
            std::fs::read_to_string(copy.join("Gemfile.lock")).unwrap(),
            lock(),
            "{command:?}"
        );
        assert!(!copy.join(".socket/vendor/gem").exists(), "{command:?}");
    }
}

/// The hosted pair of the project: the gem pinned to the gem patch's
/// registry (a snapshot URL), every platform entry in its section.
fn write_hosted_project(root: &Path) -> (String, String) {
    let registry =
        format!("https://patch.socket.dev/patch-registry/gem/11111111-1111-4111-8111-111111111111/{UUID}/s/4/");
    let gemfile = format!(
        "source \"https://rubygems.org\"\n\ngem \"{NAME}\", \"{VERSION}\", source: \"{registry}\"\n"
    );
    let lock = format!(
        "GEM\n  remote: {registry}\n  specs:\n    {NAME} ({VERSION}-{DARWIN})\n    {NAME} \
         ({VERSION}-{LINUX})\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  \
         {DARWIN}\n  {LINUX}\n\nDEPENDENCIES\n  {NAME} (= {VERSION})!\n\nBUNDLED WITH\n   2.5.22\n"
    );
    std::fs::write(root.join("Gemfile"), &gemfile).unwrap();
    std::fs::write(root.join("Gemfile.lock"), &lock).unwrap();
    (gemfile, lock)
}

/// An eject (`vendor` over a hosted lock) of a gem whose registry serves
/// upstream's own gem for one locked platform cannot vendor it: the eject
/// is refused whole, the reason names the platform, and the lock stays
/// hosted, byte for byte.
#[tokio::test]
async fn an_eject_of_a_gem_with_a_pass_through_platform_is_refused_whole() {
    let server = service(&[LINUX], &[DARWIN]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (gemfile, lock) = write_hosted_project(root);

    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 1, "{env:#}\n{stderr}");
    assert_eq!(env["error"]["code"], "eject_refused", "{env:#}");
    let failed = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["action"] == "failed")
        .unwrap_or_else(|| panic!("a failed event: {env:#}"));
    assert_eq!(
        failed["errorCode"], "vendor_prebuilt_required",
        "{failed:#}"
    );
    assert_eq!(
        failed["error"],
        format!(
            "{NAME}@{VERSION} is not vendored: no patched build yet for {DARWIN} ({LINUX} has \
             one). Vendored mode needs every locked platform; the gem stays hosted."
        )
        .as_str(),
        "{failed:#}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile")).unwrap(),
        gemfile
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile.lock")).unwrap(),
        lock
    );
    assert!(!root.join(".socket/vendor").exists());
    assert_eq!(downloads(&server).await, Vec::<String>::new());
}

/// The same hosted gem once every locked platform has a patched build:
/// the eject vendors it, one tree per platform, under the gem's patch.
#[tokio::test]
async fn an_eject_of_a_hosted_platform_gem_vendors_every_platform() {
    let server = service(&[DARWIN, LINUX], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_hosted_project(root);

    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_per_platform_gem(&env, "applied", "");
    for platform in [DARWIN, LINUX] {
        assert_eq!(
            std::fs::read(tree(root, platform).join(LIB)).unwrap(),
            PATCHED
        );
    }
    let lock = std::fs::read_to_string(root.join("Gemfile.lock")).unwrap();
    assert!(
        lock.starts_with(&format!(
            "PATH\n  remote: .socket/vendor/gem/{UUID}/{NAME}-{VERSION}\n"
        )),
        "{lock}"
    );
    assert!(!lock.contains("patch-registry"), "{lock}");
}

/// What a package search returns for the gem: the patch of the gem itself
/// and, beside it, the patch of each platform gem. Only the gem's own
/// patch has a view to download.
async fn mount_search(server: &MockServer) {
    let offers = [
        (UUID, format!("{PURL}?platform=ruby")),
        (DARWIN_UUID, format!("{PURL}?platform={DARWIN}")),
        (LINUX_UUID, format!("{PURL}?platform={LINUX}")),
    ];
    let batch: Vec<serde_json::Value> = offers
        .iter()
        .map(|(uuid, purl)| {
            serde_json::json!({
                "uuid": uuid, "purl": purl, "tier": "free", "cveIds": [CVE],
                "ghsaIds": [GHSA], "severity": "high", "title": "a synthetic vulnerability"
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(wm_path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{ "purl": PURL, "patches": batch }],
            "canAccessPaidPatches": true,
        })))
        .mount(server)
        .await;
    let view = patch_view();
    let found: Vec<serde_json::Value> = offers
        .iter()
        .map(|(uuid, purl)| {
            serde_json::json!({
                "uuid": uuid, "purl": purl, "publishedAt": "2026-01-01T00:00:00Z",
                "description": "synthetic", "license": "MIT", "tier": "free",
                "vulnerabilities": view["vulnerabilities"]
            })
        })
        .collect();
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": found,
            "canAccessPaidPatches": true,
        })))
        .mount(server)
        .await;
}

/// Install the darwin platform gem of the project the way `bundle install
/// --path vendor/bundle` leaves it, and return its directory.
fn install_darwin_gem(root: &Path) -> std::path::PathBuf {
    let leaf = format!("{NAME}-{VERSION}-{DARWIN}");
    let bundle = root.join("vendor").join("bundle");
    let gem_dir = bundle.join("gems").join(&leaf);
    std::fs::create_dir_all(gem_dir.join("lib").join(NAME)).unwrap();
    std::fs::write(gem_dir.join(LIB), PRISTINE).unwrap();
    std::fs::write(gem_dir.join(SO), DARWIN.as_bytes()).unwrap();
    std::fs::create_dir_all(bundle.join("specifications")).unwrap();
    std::fs::write(
        bundle
            .join("specifications")
            .join(format!("{leaf}.gemspec")),
        stub(DARWIN),
    )
    .unwrap();
    gem_dir
}

/// `scan --mode vendored` over a project whose installed copy of the gem
/// is one platform's gem, with a package search that returns the patches
/// of the platform gems beside the gem's own. The gem is vendored through
/// its own patch alone, as one tree per locked platform: the platform
/// gems' patches are no packages of their own (no download of their
/// records, no failure), and the installed copy, which is one platform's
/// at most, does not decide what is vendored.
#[tokio::test]
async fn a_vendored_scan_takes_the_gem_through_its_own_patch_alone() {
    let server = service(&[DARWIN, LINUX], &[]).await;
    mount_search(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("Gemfile"), GEMFILE).unwrap();
    std::fs::write(root.join("Gemfile.lock"), lock()).unwrap();
    let gem_dir = install_darwin_gem(root);

    let (code, env, stderr) = run_json(
        root,
        &["scan", "--json", "--mode", "vendored", "--yes"],
        &server.uri(),
    );
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["failed"], 0, "{env:#}");
    assert_per_platform_gem(&env, "applied", "");
    for platform in [DARWIN, LINUX] {
        assert_eq!(
            std::fs::read(tree(root, platform).join(LIB)).unwrap(),
            PATCHED
        );
    }
    // Nothing is said of a platform gem's patch but the tree vendored from
    // it, and its record is never asked for.
    for event in env["events"].as_array().unwrap() {
        let own = [DARWIN_UUID, LINUX_UUID].contains(&event["uuid"].as_str().unwrap_or_default());
        assert!(
            !own || event["details"]["gemFix"] == UUID,
            "a platform gem's patch as a package of its own: {event:#}"
        );
    }
    let requests = server.received_requests().await.unwrap();
    let views: Vec<&str> = requests
        .iter()
        .map(|request| request.url.path())
        .filter(|path| path.contains("/patches/view/"))
        .collect();
    assert!(!views.is_empty(), "the gem's own record is downloaded");
    assert!(
        views.iter().all(|path| path.ends_with(UUID)),
        "only the gem's own record: {views:?}"
    );
    assert_eq!(
        std::fs::read(gem_dir.join(LIB)).unwrap(),
        PRISTINE,
        "the installed copy is not touched"
    );
}

const SCAN: &[&str] = &["scan", "--json", "--mode", "vendored", "--yes"];

/// `scan --mode vendored` over a lock that pins the gem hosted takes it
/// over once every locked platform has a patched build: the upstream entry
/// is restored and the gem vendored, one tree per platform.
#[tokio::test]
async fn a_vendored_scan_takes_over_a_hosted_platform_gem() {
    let server = service(&[DARWIN, LINUX], &[]).await;
    mount_search(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_hosted_project(root);
    install_darwin_gem(root);

    let (code, env, stderr) = run_json(root, SCAN, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_per_platform_gem(&env, "applied", "");
    let lock = std::fs::read_to_string(root.join("Gemfile.lock")).unwrap();
    assert!(
        lock.starts_with(&format!(
            "PATH\n  remote: .socket/vendor/gem/{UUID}/{NAME}-{VERSION}\n"
        )),
        "{lock}"
    );
    assert!(!lock.contains("patch-registry"), "{lock}");
}

/// The same takeover while the registry serves upstream's own gem for one
/// locked platform: the gem is not vendored and stays hosted, byte for
/// byte, the run does not fail, and its one line says the pin stays.
#[tokio::test]
async fn a_vendored_scan_leaves_a_hosted_gem_with_a_pass_through_platform_hosted() {
    let server = service(&[LINUX], &[DARWIN]).await;
    mount_search(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (gemfile, lock) = write_hosted_project(root);
    install_darwin_gem(root);

    let (code, env, stderr) = run_json(root, SCAN, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["failed"], 0, "{env:#}");
    assert_eq!(env["summary"]["applied"], 0, "{env:#}");
    let skipped = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["errorCode"] == "vendor_prebuilt_platform_pending")
        .unwrap_or_else(|| panic!("the pending skip: {env:#}"));
    assert_eq!(skipped["action"], "skipped", "{skipped:#}");
    assert_eq!(
        skipped["reason"],
        format!(
            "{NAME}@{VERSION} is not vendored: no patched build yet for {DARWIN} ({LINUX} has \
             one). Vendored mode needs every locked platform; the gem stays hosted."
        )
        .as_str(),
        "{skipped:#}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile")).unwrap(),
        gemfile
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile.lock")).unwrap(),
        lock
    );
    assert!(!root.join(".socket/vendor/gem").exists());
    assert_eq!(downloads(&server).await, Vec::<String>::new());
}

/// `get <purl> --mode vendored` for the gem: the search returns the
/// patches of its platform gems beside its own, and the gem is vendored
/// through its own patch alone, one tree per locked platform, with
/// nothing downloaded or reported for the others as packages.
#[tokio::test]
async fn a_vendored_get_takes_the_gem_through_its_own_patch_alone() {
    let server = service(&[DARWIN, LINUX], &[]).await;
    mount_search(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("Gemfile"), GEMFILE).unwrap();
    std::fs::write(root.join("Gemfile.lock"), lock()).unwrap();

    let (code, env, stderr) = run_json(
        root,
        &["get", PURL, "--json", "--mode", "vendored", "--yes"],
        &server.uri(),
    );
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["failed"], 0, "{env:#}");
    assert_per_platform_gem(&env, "applied", "");
    for platform in [DARWIN, LINUX] {
        assert_eq!(
            std::fs::read(tree(root, platform).join(LIB)).unwrap(),
            PATCHED
        );
    }
    let requests = server.received_requests().await.unwrap();
    let views: Vec<&str> = requests
        .iter()
        .map(|request| request.url.path())
        .filter(|path| path.contains("/patches/view/"))
        .collect();
    assert!(
        !views.is_empty() && views.iter().all(|path| path.ends_with(UUID)),
        "only the gem's own record is downloaded: {views:?}"
    );
}

/// The commands that vendor the gem, as a person runs them.
const VENDOR_IT: &[&str] = &["vendor", "--vendor-source", "service"];
const SCAN_IT: &[&str] = &["scan", "--mode", "vendored", "--yes"];
const GET_IT: &[&str] = &["get", PURL, "--mode", "vendored", "--yes"];

/// `command` with `more` appended.
fn with<'a>(command: &[&'a str], more: &[&'a str]) -> Vec<&'a str> {
    command.iter().chain(more).copied().collect()
}

/// A project for `command` with nothing vendored: `vendor` takes the patch
/// from the manifest record, `scan` finds the gem installed and `get` is
/// told it.
fn fresh_project(command: &[&str]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    match command[0] {
        "vendor" => write_project(root),
        other => {
            std::fs::write(root.join("Gemfile"), GEMFILE).unwrap();
            std::fs::write(root.join("Gemfile.lock"), lock()).unwrap();
            if other == "scan" {
                install_darwin_gem(root);
            }
        }
    }
    tmp
}

/// The Gemfile and the lock are as [`fresh_project`] wrote them, and no
/// vendored artifact or ledger exists.
fn assert_nothing_vendored(root: &Path) {
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile")).unwrap(),
        GEMFILE
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile.lock")).unwrap(),
        lock()
    );
    assert!(!root.join(".socket/vendor").exists(), "nothing is written");
}

/// The lines of `stderr` that name the gem.
fn said_of_the_gem(stderr: &str) -> Vec<&str> {
    stderr.lines().filter(|line| line.contains(NAME)).collect()
}

/// The references a run asks for when every locked platform is named a
/// patch: the gem patch's, then the platform patches' in one request.
fn both_references(uuid: &str) -> [Vec<String>; 2] {
    [
        vec![uuid.to_string()],
        vec![DARWIN_UUID.to_string(), LINUX_UUID.to_string()],
    ]
}

/// `env` is a run that left the gem alone as the one counted, benign skip
/// of a gem with a locked platform that has no patched build, worded
/// `line`.
fn assert_pending_skip(env: &serde_json::Value, line: &str) {
    assert_eq!(env["status"], "success", "{env:#}");
    for (count, n) in [
        ("skipped", 1),
        ("applied", 0),
        ("verified", 0),
        ("failed", 0),
    ] {
        assert_eq!(env["summary"][count], n, "summary.{count}: {env:#}");
    }
    let skipped: Vec<&serde_json::Value> = crate::common::envelope::events(env)
        .iter()
        .filter(|event| event["action"] == "skipped")
        .collect();
    assert_eq!(skipped.len(), 1, "{env:#}");
    assert_eq!(
        skipped[0]["errorCode"], "vendor_prebuilt_platform_pending",
        "{env:#}"
    );
    assert_eq!(skipped[0]["reason"], line, "{env:#}");
}

/// Every way to run `command` over a fresh project against `server`, a
/// dry run and a wet run, for a person and as `--json`, leaves the gem
/// alone with the one `line` on stderr and the same counted benign skip:
/// exit 0, no "would vendor", nothing written and nothing downloaded. Each
/// of the four runs asks for `references` and nothing else.
async fn assert_dry_and_wet_runs_skip_alike(
    server: &MockServer,
    command: &[&str],
    line: &str,
    references: &[Vec<String>],
) {
    let project = fresh_project(command);
    let root = project.path();
    let would = match command[0] {
        "vendor" => "Would vendor 0 packages; 1 skipped.",
        _ => {
            "[dry-run] Would download and vendor 0 of 1 patch (1 would be skipped). No changes \
             made."
        }
    };
    for (dry_run, summary) in [(true, would), (false, "Vendored 0 packages; 1 skipped.")] {
        let flags: &[&str] = if dry_run { &["--dry-run"] } else { &[] };
        let args = with(command, flags);
        let (code, stdout, stderr) = run(root, &args, &server.uri());
        assert_eq!(code, 0, "{args:?}\n{stdout}\n{stderr}");
        assert_eq!(said_of_the_gem(&stderr), [line], "{args:?}\n{stderr}");
        assert!(stdout.contains(summary), "{args:?}\n{stdout}");
        assert_nothing_vendored(root);

        let args = with(&args, &["--json"]);
        let (code, env, stderr) = run_json(root, &args, &server.uri());
        assert_eq!(code, 0, "{args:?}\n{env:#}\n{stderr}");
        assert_eq!(env["dryRun"], dry_run, "{env:#}");
        assert_pending_skip(&env, line);
        assert_nothing_vendored(root);
    }
    assert_eq!(
        reference_requests(server).await,
        [references, references, references, references].concat(),
        "{command:?}: each run's requests"
    );
    assert_eq!(downloads(server).await, Vec::<String>::new(), "{command:?}");
}

/// Every dry run of a gem with a patched build of every locked platform
/// says what the wet run does: it would vendor the gem, reported once per
/// platform gem under that gem's own patch (`verified`, where the wet run
/// reports `applied`), one package for a person, and nothing is written.
/// `scan` and `get` ask for the references the wet run asks for and
/// download nothing; `vendor --dry-run` goes on to download and verify the
/// gems, as it does for every package.
#[tokio::test]
async fn every_dry_run_previews_a_fully_patched_gem_once_per_platform_gem() {
    for command in [VENDOR_IT, SCAN_IT, GET_IT] {
        let server = service(&[DARWIN, LINUX], &[]).await;
        mount_search(&server).await;
        let project = fresh_project(command);
        let root = project.path();

        let args = with(command, &["--dry-run", "--json"]);
        let (code, dry, stderr) = run_json(root, &args, &server.uri());
        assert_eq!(code, 0, "{args:?}\n{dry:#}\n{stderr}");
        assert_eq!(dry["status"], "success", "{dry:#}");
        assert_per_platform_gem(&dry, "verified", "");
        for (count, n) in [
            ("verified", 2),
            ("applied", 0),
            ("skipped", 0),
            ("failed", 0),
        ] {
            assert_eq!(dry["summary"][count], n, "summary.{count}: {dry:#}");
        }
        assert_eq!(
            reference_requests(&server).await,
            both_references(UUID),
            "{command:?}: the wet run's reference requests"
        );
        let downloaded = downloads(&server).await.len();
        match command[0] {
            "vendor" => assert_eq!(downloaded, 4, "a gem and a stub per platform, verified"),
            _ => assert_eq!(downloaded, 0, "{command:?} downloads nothing"),
        }
        assert_nothing_vendored(root);

        let args = with(command, &["--dry-run"]);
        let (code, stdout, stderr) = run(root, &args, &server.uri());
        assert_eq!(code, 0, "{args:?}\n{stdout}\n{stderr}");
        let would = match command[0] {
            "vendor" => "Would vendor 1 package.",
            _ => "[dry-run] Would download and vendor 1 patch. No changes made.",
        };
        assert!(stdout.contains(would), "{args:?}\n{stdout}");
        assert_eq!(said_of_the_gem(&stderr), Vec::<&str>::new(), "{stderr}");
        assert_nothing_vendored(root);

        let args = with(command, &["--json"]);
        let (code, wet, stderr) = run_json(root, &args, &server.uri());
        assert_eq!(code, 0, "{args:?}\n{wet:#}\n{stderr}");
        assert_per_platform_gem(&wet, "applied", "");
        assert_eq!(wet["summary"]["applied"], 2, "{wet:#}");
        assert_eq!(
            gem_events(&dry, "verified"),
            gem_events(&wet, "applied"),
            "{command:?}: the dry run names the platform gems the wet run vendors"
        );
        for platform in [DARWIN, LINUX] {
            assert_eq!(
                std::fs::read(tree(root, platform).join(LIB)).unwrap(),
                PATCHED
            );
        }
    }
}

/// Every dry run of a gem with a locked platform that has no patched build
/// says what the wet run says, and neither claims to vendor it: the gem
/// patch's reference lists upstream's own gem for the platform, so that
/// one request is all a run makes.
#[tokio::test]
async fn every_dry_run_says_the_wet_runs_line_for_a_platform_with_no_patched_build() {
    let line = format!(
        "{NAME}@{VERSION} is not vendored: no patched build yet for {DARWIN} ({LINUX} has one). \
         Vendored mode needs every locked platform; `scan --mode hosted` can patch the others now."
    );
    for command in [VENDOR_IT, SCAN_IT, GET_IT] {
        let server = service(&[LINUX], &[DARWIN]).await;
        mount_search(&server).await;
        assert_dry_and_wet_runs_skip_alike(&server, command, &line, &[vec![UUID.to_string()]])
            .await;
    }
}

/// A patched build the gem patch names, whose own patch is not served, is
/// no failure: still being built (`pending_build`) the platform has no
/// patched build yet, and not granted (`forbidden`) none available. Every
/// command, dry run or not, says so in the same one line and leaves the
/// gem alone. Each run learns it from the platform patches' references,
/// its second request, before it downloads anything.
#[tokio::test]
async fn a_platform_patch_that_is_not_served_is_the_same_skip_in_every_dry_and_wet_run() {
    for (status, none) in [
        ("pending_build", "no patched build yet for"),
        ("forbidden", "no patched build available for"),
    ] {
        let line = format!(
            "{NAME}@{VERSION} is not vendored: {none} {DARWIN} ({LINUX} has one). Vendored mode \
             needs every locked platform; `scan --mode hosted` can patch the others now."
        );
        for command in [VENDOR_IT, SCAN_IT, GET_IT] {
            let server = service_of(UUID, &[(DARWIN, Some(status)), (LINUX, None)], &[]).await;
            mount_search(&server).await;
            assert_dry_and_wet_runs_skip_alike(&server, command, &line, &both_references(UUID))
                .await;
        }
    }
}

/// A newer patch of a gem already vendored, with a platform patch that is
/// not served: the vendored copy of the earlier patch stays wired and
/// untouched, the run exits 0, and its one line says that copy stays in
/// force, in a dry run as in a wet one.
#[tokio::test]
async fn an_unserved_platform_patch_keeps_the_vendored_copy_of_an_earlier_patch() {
    let server = service(&[DARWIN, LINUX], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root);
    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    let read = |file: &str| std::fs::read_to_string(root.join(file)).unwrap();
    let vendored = (read("Gemfile"), read("Gemfile.lock"), ledger(root));
    write_manifest(root, UUID_B);

    for (status, none) in [
        ("pending_build", "no patched build yet for"),
        ("forbidden", "no patched build available for"),
    ] {
        let newer = service_of(UUID_B, &[(DARWIN, Some(status)), (LINUX, None)], &[]).await;
        let line = format!(
            "{NAME}@{VERSION} was not brought up to date: {none} {DARWIN} ({LINUX} has one). \
             Vendored mode needs every locked platform; its vendored copy of an earlier patch \
             stays in force as it is."
        );
        for flags in [&["--dry-run"][..], &[]] {
            let args = with(VENDOR_IT, flags);
            let (code, stdout, stderr) = run(root, &args, &newer.uri());
            assert_eq!(code, 0, "{args:?}\n{stdout}\n{stderr}");
            assert_eq!(said_of_the_gem(&stderr), [line.as_str()], "{stderr}");
            let args = with(&args, &["--json"]);
            let (code, env, stderr) = run_json(root, &args, &newer.uri());
            assert_eq!(code, 0, "{args:?}\n{env:#}\n{stderr}");
            assert_pending_skip(&env, &line);
        }
        assert_eq!(downloads(&newer).await, Vec::<String>::new());
        assert_eq!(
            (read("Gemfile"), read("Gemfile.lock"), ledger(root)),
            vendored,
            "{status}: the earlier patch stays wired and recorded"
        );
        for platform in [DARWIN, LINUX] {
            assert_eq!(
                std::fs::read(tree(root, platform).join(SO)).unwrap(),
                platform.as_bytes()
            );
        }
        assert!(!root.join(format!(".socket/vendor/gem/{UUID_B}")).exists());
    }
}

/// What stays a failure when a platform patch is not served. A copy the
/// lock is already wired to, with a damaged tree, cannot wait: its restore
/// from the patches the ledger records fails, and the copy stays as it
/// was. An eject of the gem's hosted pin is all-or-nothing: it is refused
/// whole and the lock stays hosted, byte for byte.
#[tokio::test]
async fn an_unserved_platform_patch_still_fails_a_damaged_wired_copy_and_an_eject() {
    for (status, none, restore_says) in [
        (
            "pending_build",
            "no patched build yet for",
            "is still building",
        ),
        ("forbidden", "no patched build available for", "Forbidden"),
    ] {
        let server = service(&[DARWIN, LINUX], &[]).await;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_project(root);
        let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
        assert_eq!(code, 0, "{env:#}\n{stderr}");
        std::fs::write(tree(root, LINUX).join(SO), b"another binary").unwrap();
        let unserved = service_of(UUID, &[(DARWIN, Some(status)), (LINUX, None)], &[]).await;
        let (code, env, stderr) = run_json(root, VENDOR, &unserved.uri());
        assert_eq!(code, 1, "{env:#}\n{stderr}");
        let failed = find_event(&env, "failed", Some("vendor_redownload_failed"));
        let why = failed["error"].as_str().unwrap_or_default();
        assert!(why.contains(restore_says), "{failed:#}");
        assert_eq!(
            std::fs::read(tree(root, LINUX).join(SO)).unwrap(),
            b"another binary",
            "the copy stays as it was"
        );
        assert_eq!(downloads(&unserved).await, Vec::<String>::new());

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (gemfile, lock) = write_hosted_project(root);
        let (code, env, stderr) = run_json(root, VENDOR, &unserved.uri());
        assert_eq!(code, 1, "{env:#}\n{stderr}");
        assert_eq!(env["error"]["code"], "eject_refused", "{env:#}");
        let failed = find_event(&env, "failed", Some("vendor_prebuilt_required"));
        assert_eq!(
            failed["error"],
            format!(
                "{NAME}@{VERSION} is not vendored: {none} {DARWIN} ({LINUX} has one). Vendored \
                 mode needs every locked platform; the gem stays hosted."
            )
            .as_str(),
            "{failed:#}"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("Gemfile")).unwrap(),
            gemfile
        );
        assert_eq!(
            std::fs::read_to_string(root.join("Gemfile.lock")).unwrap(),
            lock
        );
        assert!(!root.join(".socket/vendor").exists());
        assert_eq!(downloads(&unserved).await, Vec::<String>::new());
    }
}

/// `scan --mode vendored` over a lock that pins the gem hosted, while a
/// locked platform has no patched build (the registry serves upstream's
/// own gem for it, or the patch of its build is still being built): the
/// dry run and the wet run both say the gem stays hosted, and it does,
/// byte for byte.
#[tokio::test]
async fn a_takeover_of_a_hosted_gem_with_an_unpatched_platform_stays_hosted_dry_or_wet() {
    let line = format!(
        "{NAME}@{VERSION} is not vendored: no patched build yet for {DARWIN} ({LINUX} has one). \
         Vendored mode needs every locked platform; the gem stays hosted."
    );
    let pass_through = service(&[LINUX], &[DARWIN]).await;
    let building = service_of(UUID, &[(DARWIN, Some("pending_build")), (LINUX, None)], &[]).await;
    for server in [pass_through, building] {
        mount_search(&server).await;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (gemfile, lock) = write_hosted_project(root);
        install_darwin_gem(root);
        for flags in [&["--dry-run"][..], &[]] {
            let args = with(SCAN_IT, flags);
            let (code, stdout, stderr) = run(root, &args, &server.uri());
            assert_eq!(code, 0, "{args:?}\n{stdout}\n{stderr}");
            assert_eq!(said_of_the_gem(&stderr), [line.as_str()], "{stderr}");
            let args = with(&args, &["--json"]);
            let (code, env, stderr) = run_json(root, &args, &server.uri());
            assert_eq!(code, 0, "{args:?}\n{env:#}\n{stderr}");
            assert_pending_skip(&env, &line);
            assert_eq!(
                std::fs::read_to_string(root.join("Gemfile")).unwrap(),
                gemfile
            );
            assert_eq!(
                std::fs::read_to_string(root.join("Gemfile.lock")).unwrap(),
                lock
            );
            assert!(!root.join(".socket/vendor/gem").exists());
        }
        assert_eq!(downloads(&server).await, Vec::<String>::new());
    }
}

/// No run tells a gem that stays hosted to run hosted mode. A hosted gem
/// with a locked platform that has no patched build reaches the vendored
/// backend three ways: `scan` and `get` take it over (their dry runs ask
/// the patch service with no record of the patch), and `vendor` ejects it,
/// which is all or nothing and so fails. Each of them, dry or wet, for a
/// person and as `--json`, says that the gem stays hosted, and nothing it
/// prints names `--mode hosted`, which is what a gem with no hosted pin is
/// told to run.
#[tokio::test]
async fn no_run_tells_a_gem_that_stays_hosted_to_run_hosted_mode() {
    let stays = format!(
        "{NAME}@{VERSION} is not vendored: no patched build yet for {DARWIN} ({LINUX} has one). \
         Vendored mode needs every locked platform; the gem stays hosted."
    );
    for command in [SCAN_IT, GET_IT, VENDOR_IT] {
        let server = service(&[LINUX], &[DARWIN]).await;
        mount_search(&server).await;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (gemfile, lock) = write_hosted_project(root);
        if command[0] == "scan" {
            install_darwin_gem(root);
        }
        let exit = i32::from(command[0] == "vendor");
        for flags in [&["--dry-run"][..], &[]] {
            for json in [&[][..], &["--json"]] {
                let args = with(&with(command, flags), json);
                let (code, stdout, stderr) = run(root, &args, &server.uri());
                assert_eq!(code, exit, "{args:?}\n{stdout}\n{stderr}");
                let said = format!("{stdout}\n{stderr}");
                assert!(said.contains(&stays), "{args:?}\n{said}");
                assert!(
                    !said.contains("--mode hosted"),
                    "{args:?} names hosted mode to a gem that is hosted:\n{said}"
                );
                assert_eq!(
                    std::fs::read_to_string(root.join("Gemfile")).unwrap(),
                    gemfile
                );
                assert_eq!(
                    std::fs::read_to_string(root.join("Gemfile.lock")).unwrap(),
                    lock
                );
                assert!(!root.join(".socket/vendor/gem").exists());
            }
        }
        assert_eq!(downloads(&server).await, Vec::<String>::new());
    }

    // The same platforms for a gem with no hosted pin: hosted mode is what
    // patches the others.
    let server = service(&[LINUX], &[DARWIN]).await;
    let project = fresh_project(VENDOR_IT);
    let (code, stdout, stderr) = run(project.path(), VENDOR_IT, &server.uri());
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stderr.contains("`scan --mode hosted` can patch the others now."),
        "{stderr}"
    );
    assert!(!stderr.contains("stays hosted"), "{stderr}");
}

/// Offline, the patch service may not be asked, so no dry run promises to
/// vendor the gem. `vendor --dry-run --offline` ends as the wet run does,
/// in the same failure, and `scan` and `get` refuse `--offline` outright.
/// No request is made.
#[tokio::test]
async fn an_offline_dry_run_asks_nothing_and_promises_nothing() {
    let server = service(&[DARWIN, LINUX], &[]).await;
    mount_search(&server).await;
    let project = fresh_project(VENDOR_IT);
    let root = project.path();
    for flags in [&["--offline", "--dry-run"][..], &["--offline"]] {
        let args = with(VENDOR_IT, flags);
        let (code, stdout, stderr) = run(root, &args, &server.uri());
        assert_eq!(code, 1, "{args:?}\n{stdout}\n{stderr}");
        assert!(!stdout.contains("vendor 1 package"), "{stdout}");
        let args = with(&args, &["--json"]);
        let (code, env, stderr) = run_json(root, &args, &server.uri());
        assert_eq!(code, 1, "{args:?}\n{env:#}\n{stderr}");
        assert_eq!(
            gem_events(&env, "failed"),
            [(PURL, "", "", "", "vendor_service_offline_conflict")],
            "{env:#}"
        );
        assert_eq!(env["summary"]["verified"], 0, "{env:#}");
        assert_nothing_vendored(root);
    }
    for command in [SCAN_IT, GET_IT] {
        let project = fresh_project(command);
        let args = with(command, &["--offline", "--dry-run", "--json"]);
        let (code, env, stderr) = run_json(project.path(), &args, &server.uri());
        assert_ne!(code, 0, "{args:?}\n{env:#}\n{stderr}");
        assert_eq!(env["error"]["code"], "offline_unsupported", "{env:#}");
    }
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        0,
        "offline"
    );
}
