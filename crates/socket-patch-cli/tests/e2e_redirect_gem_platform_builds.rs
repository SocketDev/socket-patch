//! Hosted mode over a gem the Bundler lock names as precompiled platform
//! builds (`nokogiri (1.19.3-x86_64-linux-gnu)`), against a wiremock patch
//! API (real binary, no Ruby or Bundler: nothing is installed here).
//!
//! The gem's fix is one patch, the ruby-platform gem's. Its reference lists
//! every platform gem of the version (`gemBuilds`): the sha256 the patch
//! registry serves and, where there is a patched build, the patch it comes
//! from. A platform with none is served as upstream's own gem. So:
//!
//! * every locked build moves to the registry together as soon as one of
//!   them is patched, each pinned to the sha256 listed for it, with no
//!   warning;
//! * the run reports the gem per locked build: an `applied` event under
//!   the build's own patch, an uncounted `gem_upstream_build_kept` event
//!   for a build that stays upstream's gem, and one plain line for people;
//! * a gem with no patched build for any locked platform is left where it
//!   is, under a quiet skip;
//! * a later run on the same registry snapshot changes nothing, and one on
//!   a newer snapshot refreshes the URL and says which builds it found
//!   patched;
//! * a platform the registry does not list, or a reference with no list at
//!   all, leaves the gem alone under `redirect_gem_platform_unsupported`.

use std::path::Path;

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const DEP: &str = "platform-probe";
const DEP_VERSION: &str = "1.19.3";
const PURL: &str = "pkg:gem/platform-probe@1.19.3";
/// The gem's patch: the one fix, selected as for any gem.
const UUID: &str = "7b1e4f3a-2c5d-4e6f-8a9b-0c1d2e3f4a5b";
/// The patches of its patched platform builds.
const ARM_UUID: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const LINUX_UUID: &str = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
const TOKEN: &str = "66666666-6666-4666-8666-666666666666";
const GHSA: &str = "GHSA-plat-form-gems";
/// Shaped like a Socket API token, so no run warns about the token itself.
const API_TOKEN: &str = "sktsec_00000000000000000000000000000000000000000000_api";

const ARM: &str = "arm64-darwin";
const LINUX: &str = "x86_64-linux-gnu";

/// The sha256 a lock pins before any run: upstream's own platform gems.
const ARM_UPSTREAM: &str = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
const LINUX_UPSTREAM: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";
/// The sha256 of the patched gems.
const RUBY_PATCHED: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
const ARM_PATCHED: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const LINUX_PATCHED: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
const RACC: &str = "5555555555555555555555555555555555555555555555555555555555555555";

/// One platform gem as a reference lists it (`gemBuilds`): its platform,
/// the sha256 the registry serves, and the patch of its patched build
/// (`None`: the registry serves upstream's own gem).
type Listed = (&'static str, &'static str, Option<&'static str>);

/// `arm64-darwin` on upstream's gem, `x86_64-linux-gnu` patched.
const ONE_PATCHED: [Listed; 2] = [
    (ARM, ARM_UPSTREAM, None),
    (LINUX, LINUX_PATCHED, Some(LINUX_UUID)),
];
const BOTH_PATCHED: [Listed; 2] = [
    (ARM, ARM_PATCHED, Some(ARM_UUID)),
    (LINUX, LINUX_PATCHED, Some(LINUX_UUID)),
];
const NONE_PATCHED: [Listed; 2] = [(ARM, ARM_UPSTREAM, None), (LINUX, LINUX_UPSTREAM, None)];

/// The registry URL a reference names: with the snapshot level when it
/// lists platform gems, plain when it does not.
fn index_url(api: &str, snapshot: Option<u32>) -> String {
    let root = format!("{api}/patch-registry/gem/{TOKEN}/{UUID}/");
    match snapshot {
        Some(snapshot) => format!("{root}s/{snapshot}"),
        None => root,
    }
}

/// Mount the patch API of the one gem patch. `listing` is the reference's
/// `gemBuilds` and the snapshot its registry URL names; `None` is a
/// reference with no list (a patch of the ruby gem alone).
async fn mount_api(server: &MockServer, listing: Option<(&[Listed], u32)>) {
    let mut identifiers = json!({
        "name": DEP, "version": DEP_VERSION, "gemChecksumSha256": RUBY_PATCHED,
    });
    if let Some((builds, _)) = listing {
        identifiers["gemBuilds"] = builds
            .iter()
            .map(|(platform, sha, patch)| {
                json!({ "platform": platform, "gemChecksumSha256": sha, "patchUuid": patch })
            })
            .collect();
    }
    let api = server.uri();
    let artifact =
        format!("{api}/patch/gem/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.gem");
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{ "purl": PURL, "patches": [{
                "uuid": UUID, "purl": PURL, "tier": "free", "cveIds": [],
                "ghsaIds": [GHSA], "severity": "high", "title": "platform gem fixture",
            }]}],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [{
                "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": { GHSA: {
                    "cves": ["CVE-2026-5555"], "summary": "s", "severity": "high",
                    "description": "d",
                }},
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { UUID: {
                "status": "granted",
                "url": artifact,
                "purl": PURL,
                "artifacts": [{
                    "kind": "tarball", "url": artifact,
                    "integrity": { "sha256": RUBY_PATCHED },
                }],
                "registryOverride": {
                    "kind": "rubygems-compact-index",
                    "indexUrl": index_url(&api, listing.map(|(_, snapshot)| snapshot)),
                    "identifiers": identifiers,
                },
            }}
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "lib/platform_probe.rb": {
                "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64),
            }},
            "vulnerabilities": { GHSA: {
                "cves": ["CVE-2026-5555"], "summary": "s", "severity": "high",
                "description": "d",
            }},
            "description": "x", "license": "MIT", "tier": "free",
        })))
        .mount(server)
        .await;
}

const GEMFILE: &str =
    "source \"https://rubygems.org\"\n\ngem \"platform-probe\", \"1.19.3\"\ngem \"racc\", \"1.8.1\"\n";

/// A lock that names the gem as its two platform builds, each pinned to
/// upstream's archive, beside a plain gem. `checksums: false` is the lock
/// of a Bundler that writes no `CHECKSUMS` section.
fn lock(checksums: bool) -> String {
    let mut lock = format!(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    {DEP} ({DEP_VERSION}-{ARM})\n    {DEP} \
         ({DEP_VERSION}-{LINUX})\n    racc (1.8.1)\n\nPLATFORMS\n  {ARM}\n  {LINUX}\n\nDEPENDENCIES\n  \
         {DEP} (= {DEP_VERSION})\n  racc (= 1.8.1)\n\n"
    );
    if checksums {
        lock.push_str(&format!(
            "CHECKSUMS\n  {DEP} ({DEP_VERSION}-{ARM}) sha256={ARM_UPSTREAM}\n  {DEP} \
             ({DEP_VERSION}-{LINUX}) sha256={LINUX_UPSTREAM}\n  racc (1.8.1) sha256={RACC}\n\n"
        ));
    }
    lock.push_str("BUNDLED WITH\n  4.0.15\n");
    lock
}

/// [`lock`] as a hosted run leaves it: the gem's builds under the patch
/// registry `index` (with its closing slash), pinned to `arm` and `linux`.
fn hosted_lock(index: &str, arm: &str, linux: &str) -> String {
    format!(
        "GEM\n  remote: {index}\n  specs:\n    {DEP} ({DEP_VERSION}-{ARM})\n    {DEP} \
         ({DEP_VERSION}-{LINUX})\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    racc \
         (1.8.1)\n\nPLATFORMS\n  {ARM}\n  {LINUX}\n\nDEPENDENCIES\n  {DEP} (= {DEP_VERSION})!\n  racc (= \
         1.8.1)\n\nCHECKSUMS\n  {DEP} ({DEP_VERSION}-{ARM}) sha256={arm}\n  {DEP} \
         ({DEP_VERSION}-{LINUX}) sha256={linux}\n  racc (1.8.1) sha256={RACC}\n\nBUNDLED WITH\n  4.0.15\n"
    )
}

/// [`GEMFILE`] as a hosted run leaves it.
fn hosted_gemfile(index: &str) -> String {
    GEMFILE.replace(
        "gem \"platform-probe\", \"1.19.3\"\n",
        &format!("gem \"platform-probe\", \"1.19.3\", source: \"{index}\"\n"),
    )
}

/// A project with [`GEMFILE`] and `lock`, in a new temp dir.
fn project(lock: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Gemfile"), GEMFILE).unwrap();
    std::fs::write(dir.path().join("Gemfile.lock"), lock).unwrap();
    dir
}

fn read(proj: &Path, rel: &str) -> String {
    std::fs::read_to_string(proj.join(rel)).unwrap()
}

/// `socket-patch <command…> --mode hosted` over `proj` against `api`, with
/// `extra` arguments.
fn hosted(proj: &Path, api: &str, command: &[&str], extra: &[&str]) -> (i32, String, String) {
    let mut args: Vec<&str> = command.to_vec();
    args.extend_from_slice(&[
        "--mode",
        "hosted",
        "--yes",
        "--cwd",
        proj.to_str().expect("utf8 temp path"),
        "--api-url",
        api,
        "--org",
        ORG,
        "--api-token",
        API_TOKEN,
    ]);
    args.extend_from_slice(extra);
    common::run_with_env(proj, &args, &[])
}

/// A `--json` hosted scan: exit code and envelope.
fn scan_json(proj: &Path, api: &str, extra: &[&str]) -> (i32, Value) {
    let mut args = vec!["--json"];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = hosted(proj, api, &["scan"], &args);
    let env: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
    (code, env)
}

/// The run's hosted events (`details.mode: "hosted"`), in envelope order.
fn hosted_events(env: &Value) -> Vec<Value> {
    env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| event["details"]["mode"] == "hosted")
        .cloned()
        .collect()
}

fn warning_codes(env: &Value) -> Vec<String> {
    env["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|w| w["code"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The event of a patched build: `applied` (`verified` on a dry run) under
/// the build's own patch.
fn patched_event(action: &str, platform: &str, patch: &str, newly: bool) -> Value {
    let mut details = json!({ "gemFix": UUID, "platform": platform, "mode": "hosted" });
    if newly {
        details["newlyPatched"] = json!(true);
    }
    json!({
        "action": action, "purl": format!("{PURL}?platform={platform}"), "uuid": patch,
        "details": details,
    })
}

/// The uncounted event of a build that stays upstream's gem.
fn upstream_event(platform: &str) -> Value {
    json!({
        "action": "skipped",
        "purl": format!("{PURL}?platform={platform}"),
        "errorCode": "gem_upstream_build_kept",
        "reason": format!(
            "the patch registry serves upstream's own gem for {platform}: no patched build yet"
        ),
        "details": { "gemFix": UUID, "platform": platform, "mode": "hosted" },
    })
}

/// The uuids each reference request of the run asked about, one list per
/// request, and the paths of every request that was no patch API call.
async fn requests(server: &MockServer) -> (Vec<Vec<String>>, Vec<String>) {
    let mut references = Vec::new();
    let mut other = Vec::new();
    for request in server.received_requests().await.unwrap_or_default() {
        let route = request.url.path().to_string();
        if route == format!("/v0/orgs/{ORG}/patches/package") {
            let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
            references.push(
                body["uuids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|uuid| uuid.as_str().map(str::to_string))
                    .collect(),
            );
        } else if !route.starts_with(&format!("/v0/orgs/{ORG}/patches/")) {
            other.push(route);
        }
    }
    (references, other)
}

/// Two locked platforms, one with a patched build and one without: the
/// gem moves, the platform without one keeps the sha256 it had, and the
/// run says so without a warning. One reference request, for the gem's
/// own patch, and no request to the registry.
#[tokio::test(flavor = "multi_thread")]
async fn a_gem_moves_as_soon_as_one_locked_build_is_patched() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));

    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&index, ARM_UPSTREAM, LINUX_PATCHED)
    );
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&index));
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            upstream_event(ARM),
            patched_event("applied", LINUX, LINUX_UUID, true)
        ],
        "{env}"
    );
    let summary = &env["summary"];
    assert_eq!(
        (&summary["applied"], &summary["skipped"], &summary["failed"]),
        (&json!(1), &json!(0), &json!(0)),
        "the build on upstream's gem is counted nowhere: {env}"
    );
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        json!(["Gemfile", "Gemfile.lock"])
    );
    let (references, other) = requests(&server).await;
    assert_eq!(references, [[UUID.to_string()]], "one reference request");
    assert_eq!(other, Vec::<String>::new(), "no registry request");

    // For a person: one plain line on stdout, and nothing that warns.
    let proj = project(&lock(true));
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("Switched 1 package to hosted patches; rewrote 2 files.\n"),
        "one package, whatever its builds:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: patched for {LINUX}; upstream gem kept for {ARM} (no patched \
             build yet)\n"
        )),
        "{stdout}"
    );
    assert!(
        !stderr.contains("Warning")
            && !stderr.contains("Skipped")
            && !stderr.contains("Not hosted"),
        "{stderr}"
    );
    // `--silent` says nothing of it.
    let proj = project(&lock(true));
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &["--silent"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        !stdout.contains(DEP) && !stderr.contains(DEP),
        "{stdout}\n{stderr}"
    );
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&index, ARM_UPSTREAM, LINUX_PATCHED)
    );

    // A dry run previews the same outcome and writes nothing.
    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &api, &["--dry-run"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock(true));
    assert_eq!(
        hosted_events(&env),
        [
            upstream_event(ARM),
            patched_event("verified", LINUX, LINUX_UUID, true)
        ],
        "{env}"
    );
    let (code, stdout, _) = hosted(proj.path(), &api, &["scan"], &["--dry-run"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: would be patched for {LINUX}; upstream gem kept for {ARM} (no \
             patched build yet)\n"
        )),
        "{stdout}"
    );
}

/// Every locked build has a patched build: one `applied` event per build,
/// each under its own patch, all naming the gem's patch as their fix.
#[tokio::test(flavor = "multi_thread")]
async fn every_patched_build_is_reported_under_its_own_patch() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&BOTH_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));

    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&index, ARM_PATCHED, LINUX_PATCHED)
    );
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            patched_event("applied", ARM, ARM_UUID, true),
            patched_event("applied", LINUX, LINUX_UUID, true)
        ],
        "{env}"
    );
    assert_eq!(env["summary"]["applied"], 2, "{env}");
    assert_eq!(env["summary"]["skipped"], 0, "{env}");

    let proj = project(&lock(true));
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("Switched 1 package to hosted patches; rewrote 2 files.\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: patched for {ARM}, {LINUX}\n"
        )),
        "{stdout}"
    );
    assert!(!stderr.contains("Warning"), "{stderr}");
}

/// No locked build has a patched build yet: moving the gem would gain
/// nothing, so both files stay as they are. Exit 0, no warning, one
/// skipped event under the quiet code, and one plain line for a person
/// instead of the "No patches could be switched" block.
#[tokio::test(flavor = "multi_thread")]
async fn a_gem_with_no_patched_build_is_left_alone_quietly() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&NONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let left = format!(
        "{DEP} {DEP_VERSION}: no patched build yet for {ARM}, {LINUX}; left on its upstream \
         registry"
    );

    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock(true));
    assert_eq!(read(proj.path(), "Gemfile"), GEMFILE);
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [json!({
            "action": "skipped", "purl": PURL, "uuid": UUID,
            "errorCode": "redirect_gem_no_patched_build", "reason": left,
            "details": { "mode": "hosted" },
        })],
        "{env}"
    );
    assert_eq!(env["summary"]["skipped"], 1, "{env}");
    assert_eq!(env["summary"]["applied"], 0, "{env}");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    assert_eq!(env["redirect"]["rewrittenFiles"], json!([]));

    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains(&format!("\n{left}\n")), "{stdout}");
    assert!(
        !stderr.contains("No patches could be switched")
            && !stderr.contains("Warning")
            && !stderr.contains(DEP),
        "nothing on stderr names it:\n{stderr}"
    );
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock(true));
}

/// Later runs. On the same snapshot nothing is written and no build is
/// reported as newly patched. A newer snapshot that lists one more patched
/// build refreshes the registry URL in both files, re-pins that build's
/// sha256 alone, and the run names it. A platform the lock gains afterwards
/// is reported with the others.
#[tokio::test(flavor = "multi_thread")]
async fn later_runs_report_what_changed_since() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));

    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    let first_lock = read(proj.path(), "Gemfile.lock");
    assert_eq!(first_lock, hosted_lock(&index, ARM_UPSTREAM, LINUX_PATCHED));

    // The same snapshot again.
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), first_lock);
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&index));
    assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{env}");
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            upstream_event(ARM),
            patched_event("applied", LINUX, LINUX_UUID, false)
        ],
        "in place, not newly patched: {env}"
    );
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 package is already on hosted patches; nothing to rewrite.\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: patched for {LINUX}; upstream gem kept for {ARM} (no patched \
             build yet)\n"
        )),
        "{stdout}"
    );

    // A newer snapshot: arm64-darwin has a patched build too.
    server.reset().await;
    mount_api(&server, Some((&BOTH_PATCHED[..], 5))).await;
    let newer = format!("{}/", index_url(&api, Some(5)));
    let hosted_pair = (first_lock.clone(), hosted_gemfile(&index));
    let human = project(&hosted_pair.0);
    std::fs::write(human.path().join("Gemfile"), &hosted_pair.1).unwrap();

    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&newer, ARM_PATCHED, LINUX_PATCHED),
        "the URL and the one checksum that changed"
    );
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&newer));
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            patched_event("applied", ARM, ARM_UUID, true),
            patched_event("applied", LINUX, LINUX_UUID, false)
        ],
        "{env}"
    );
    let (code, stdout, stderr) = hosted(human.path(), &api, &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: now also patched for {ARM}; already patched for {LINUX}\n"
        )),
        "{stdout}"
    );
    assert!(!stderr.contains("Warning"), "{stderr}");
    assert_eq!(
        read(human.path(), "Gemfile.lock"),
        hosted_lock(&newer, ARM_PATCHED, LINUX_PATCHED)
    );

    // The lock gains a platform (`bundle lock --add-platform`), which the
    // registry serves as upstream's gem: it is reported with the others,
    // and nothing is rewritten for it.
    const MUSL: &str = "x86_64-linux-musl";
    let musl_sha = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
    let mut listing: Vec<Listed> = BOTH_PATCHED.to_vec();
    listing.push((MUSL, musl_sha, None));
    server.reset().await;
    mount_api(&server, Some((&listing[..], 5))).await;
    let gained = read(proj.path(), "Gemfile.lock")
        .replace(
            &format!("    {DEP} ({DEP_VERSION}-{LINUX})\n"),
            &format!("    {DEP} ({DEP_VERSION}-{LINUX})\n    {DEP} ({DEP_VERSION}-{MUSL})\n"),
        )
        .replace(
            &format!("PLATFORMS\n  {ARM}\n  {LINUX}\n"),
            &format!("PLATFORMS\n  {ARM}\n  {LINUX}\n  {MUSL}\n"),
        )
        .replace(
            &format!("  {DEP} ({DEP_VERSION}-{LINUX}) sha256={LINUX_PATCHED}\n"),
            &format!(
                "  {DEP} ({DEP_VERSION}-{LINUX}) sha256={LINUX_PATCHED}\n  {DEP} \
                 ({DEP_VERSION}-{MUSL}) sha256={musl_sha}\n"
            ),
        );
    std::fs::write(proj.path().join("Gemfile.lock"), &gained).unwrap();
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), gained);
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            patched_event("applied", ARM, ARM_UUID, false),
            patched_event("applied", LINUX, LINUX_UUID, false),
            upstream_event(MUSL),
        ],
        "{env}"
    );
}

/// A lock with no `CHECKSUMS` section (Bundler before 2.6): the gem still
/// moves, pinned by source alone, and is reported per build.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_without_checksums_still_moves() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));

    let proj = project(&lock(false));
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    let after = read(proj.path(), "Gemfile.lock");
    assert!(
        after.starts_with(&format!(
            "GEM\n  remote: {index}\n  specs:\n    {DEP} ({DEP_VERSION}-{ARM})\n    {DEP} \
             ({DEP_VERSION}-{LINUX})\n\nGEM\n  remote: https://rubygems.org/\n"
        )),
        "{after}"
    );
    assert!(!after.contains("CHECKSUMS"), "{after}");
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&index));
    assert_eq!(
        warning_codes(&env),
        ["redirect_gem_no_checksums_section"],
        "the lock's own caveat, and nothing about platforms: {env}"
    );
    assert_eq!(
        hosted_events(&env),
        [
            upstream_event(ARM),
            patched_event("applied", LINUX, LINUX_UUID, true)
        ],
        "{env}"
    );
}

/// A reference with no list at all is a patch of the ruby gem alone:
/// nothing is written and the run says why.
#[tokio::test(flavor = "multi_thread")]
async fn a_patch_with_no_list_leaves_the_gem_alone_with_a_warning() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock(true));
    assert_eq!(read(proj.path(), "Gemfile"), GEMFILE);
    assert_eq!(
        warning_codes(&env),
        ["redirect_gem_platform_unsupported"],
        "{env}"
    );
    let detail = env["warnings"][0]["detail"].as_str().unwrap();
    assert!(
        detail.contains(
            "the patch covers the ruby platform gem only (the patch registry does not list the \
             platform gems of this version)"
        ),
        "{detail}"
    );
    assert_eq!(
        hosted_events(&env),
        [json!({
            "action": "skipped", "purl": PURL, "uuid": UUID,
            "errorCode": "redirect_unconfirmed",
            "reason": "no lockfile entry pinning it could be rewritten",
            "details": { "mode": "hosted" },
        })],
        "{env}"
    );
}

/// A locked platform the list leaves out is one whose patched build is
/// still being made: a machine of that platform would be sent to a
/// registry with no gem for it, so the gem is left as it is, with no
/// warning and one plain line, and a later run over a list that has the
/// platform moves it.
#[tokio::test(flavor = "multi_thread")]
async fn a_platform_missing_from_the_list_is_waited_for_quietly() {
    let linux_only: [Listed; 1] = [(LINUX, LINUX_PATCHED, Some(LINUX_UUID))];
    let server = MockServer::start().await;
    mount_api(&server, Some((&linux_only[..], 4))).await;
    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock(true));
    assert_eq!(read(proj.path(), "Gemfile"), GEMFILE);
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    let waiting = format!(
        "{DEP} {DEP_VERSION}: the patch registry does not list {ARM} yet (a patched build is \
         still being made); left as it is until it does"
    );
    assert_eq!(
        hosted_events(&env),
        [json!({
            "action": "skipped", "purl": PURL, "uuid": UUID,
            "errorCode": "redirect_gem_build_pending",
            "reason": waiting,
            "details": { "mode": "hosted" },
        })],
        "{env}"
    );
    assert_eq!(env["summary"]["failed"], 0, "{env}");

    let (code, stdout, stderr) = hosted(proj.path(), &server.uri(), &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains(&waiting), "{stdout}");
    assert!(!stderr.contains("Warning"), "{stderr}");

    // The build is there: the list names the platform, and the gem moves.
    let later = MockServer::start().await;
    mount_api(&later, Some((&ONE_PATCHED[..], 5))).await;
    let (code, env) = scan_json(proj.path(), &later.uri(), &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert_ne!(read(proj.path(), "Gemfile.lock"), lock(true));
}

/// `get <the gem's patch> --mode hosted` writes what `scan` writes and
/// reports the gem per build the same way.
#[tokio::test(flavor = "multi_thread")]
async fn get_reports_the_gem_as_scan_does() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));

    let proj = project(&lock(true));
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["get", UUID], &["--json"]);
    let env: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&index, ARM_UPSTREAM, LINUX_PATCHED)
    );
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&index));
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            upstream_event(ARM),
            patched_event("applied", LINUX, LINUX_UUID, true)
        ],
        "{env}"
    );
    let (references, other) = requests(&server).await;
    assert_eq!(references, [[UUID.to_string()]], "one reference request");
    assert_eq!(other, Vec::<String>::new(), "no registry request");

    let proj = project(&lock(true));
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["get", UUID], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: patched for {LINUX}; upstream gem kept for {ARM} (no patched \
             build yet)\n"
        )),
        "{stdout}"
    );
    assert!(!stderr.contains("Warning"), "{stderr}");
}

/// The gem is one package to the rollout budget and to the severity floor,
/// however many of its builds are patched: a budget of one new patch admits
/// it whole, and a floor above its severity leaves it out whole.
#[tokio::test(flavor = "multi_thread")]
async fn rollout_and_the_severity_floor_count_the_gem_once() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&BOTH_PATCHED[..], 4))).await;
    let api = server.uri();

    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &api, &["--max-new-patches", "1"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(
        env["rollout"]["counts"],
        json!({ "new": 1, "deferred": 0, "upgrade": 0, "already": 0 }),
        "{env}"
    );
    assert_eq!(env["rollout"]["deferred"], json!([]), "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            patched_event("applied", ARM, ARM_UUID, true),
            patched_event("applied", LINUX, LINUX_UUID, true)
        ],
        "{env}"
    );

    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &api, &["--min-severity", "critical"]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock(true));
    assert_eq!(env["policy"]["counts"]["filtered"], 1, "{env}");
    assert_eq!(hosted_events(&env), Vec::<Value>::new(), "{env}");
}
