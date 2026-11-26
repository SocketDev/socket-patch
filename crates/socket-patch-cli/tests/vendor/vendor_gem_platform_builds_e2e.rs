//! Vendoring a gem the Bundler lock names as precompiled platform gems:
//! one tree per locked platform, each from that platform's own patch, and
//! what a run says of it (one event per platform gem, one package).
//!
//! The patch service is a stand-in that answers in the shape of the wire
//! contract: the gem patch's reference lists every platform gem of the
//! version (`registryOverride.identifiers.gemBuilds`) with the patch of
//! each patched build, and each such patch serves that platform's gem
//! (`tarball`) and stub gemspec. No Bundler runs here.

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
    serde_json::json!({
        "uuid": UUID,
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
    let server = MockServer::start().await;
    let mut results = serde_json::Map::new();
    let mut gem_builds = Vec::new();
    for platform in patched {
        let own = build_uuid(platform);
        let (gem, gemspec) = (platform_gem(platform), stub(platform));
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
        gem_builds.push(serde_json::json!({
            "platform": platform, "gemChecksumSha256": sha256_hex(&gem), "patchUuid": own
        }));
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
        "{}/patch/gem/{NAME}/{VERSION}/tok/{UUID}/{NAME}-{VERSION}.gem",
        server.uri()
    );
    results.insert(
        UUID.to_string(),
        serde_json::json!({
            "status": "granted",
            "purl": format!("{PURL}?platform=ruby"),
            "url": ruby_url,
            "artifacts": [{ "kind": "tarball", "url": ruby_url,
                            "integrity": { "sha512": sri(&ruby_gem) } }],
            "registryOverride": {
                "kind": "rubygems-compact-index",
                "indexUrl": format!("{}/patch-registry/gem/tok/{UUID}/s/4", server.uri()),
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
        .and(wm_path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(patch_view()))
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
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let view = patch_view();
    let manifest = serde_json::json!({
        "patches": {
            PURL: {
                "uuid": UUID,
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
    assert!(entry.get("gemPlatforms").is_none(), "{entry:#}");

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

/// A ledger entry that names the platforms of its copy and no patch for
/// their trees (`gemPlatforms`) still checks as one package, the next
/// vendor run records each tree's patch in its place, and it reverts. An
/// entry whose `gemBuilds` items carry fields this build does not know
/// reads as if they were not there.
#[tokio::test]
async fn ledger_entries_of_other_builds_still_check_convert_and_revert() {
    let server = service(&[DARWIN, LINUX], &[]).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root);
    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    let state_path = root.join(".socket/vendor/state.json");
    let current = ledger(root);

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
    std::fs::write(&state_path, serde_json::to_vec_pretty(&extended).unwrap()).unwrap();
    let (code, env, stderr) = run_json(root, &["vendor", "--check", "--json"], &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_per_platform_gem(&env, "verified", "vendor_check_ok");

    // Platforms only: one verdict, for the gem.
    let mut older = current.clone();
    let entry = older["entries"][PURL].as_object_mut().unwrap();
    entry.remove("gemBuilds");
    entry.insert("gemPlatforms".into(), serde_json::json!([DARWIN, LINUX]));
    std::fs::write(&state_path, serde_json::to_vec_pretty(&older).unwrap()).unwrap();
    let (code, env, stderr) = run_json(root, &["vendor", "--check", "--json"], &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(
        gem_events(&env, "verified"),
        [(PURL, "", "", "", "vendor_check_ok")],
        "{env:#}"
    );

    // The next vendor run records the patch of each tree.
    let (code, env, stderr) = run_json(root, VENDOR, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_per_platform_gem(&env, "applied", "");
    let rebuilt = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["errorCode"] == "vendor_artifact_rebuilt")
        .unwrap_or_else(|| panic!("{env:#}"));
    assert!(
        rebuilt["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("was recorded with no patch named for its platform gems"),
        "{rebuilt:#}"
    );
    let converted = ledger(root);
    assert_eq!(
        converted["entries"][PURL]["gemBuilds"],
        current["entries"][PURL]["gemBuilds"]
    );
    assert!(converted["entries"][PURL].get("gemPlatforms").is_none());
    assert_eq!(
        converted["entries"][PURL]["wiring"], current["entries"][PURL]["wiring"],
        "the wiring records ride on"
    );

    // Revert of the entry that names platforms only.
    std::fs::write(&state_path, serde_json::to_vec_pretty(&older).unwrap()).unwrap();
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
