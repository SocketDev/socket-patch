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
//!
//! The VEX document is truthful per locked build, in the run's own `--vex`
//! and in a later `socket-patch vex` over the lock the run left:
//!
//! * a patched build is `not_affected` under its own patch, a build on
//!   upstream's gem is `affected`, and no statement names a form of the gem
//!   that stands for both;
//! * the run's own document costs no request beyond the run's; a later
//!   `vex` asks for the gem patch's reference once, and for the index of
//!   the lock's registry only when the lock has no `CHECKSUMS`;
//! * a build is attested by its patch only on the sha256 the lock installs
//!   for it: one the lock pins otherwise, or that nothing could be read
//!   about (`--offline`, a failed request, an unreadable index), is said
//!   `affected`, with why and what to run. That is no failure: the run
//!   exits 0 as a success, and one warning names the gem
//!   (`vex_gem_build_unknown`);
//! * a gem locked as its ruby-platform gem alone is one pin, with no
//!   request of its own.

use std::path::Path;

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;
use common::envelope::warning_codes;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

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

/// The patch service also has a patch record per patched platform gem
/// (`pkg:gem/<name>@<version>?platform=<platform>`), which a search
/// returns beside the gem's own. Agent mode takes those; a hosted run
/// patches the gem through its own patch alone. The platform gem's record
/// is no selection of its own: one reference request for the one patch,
/// no skip, and a later run offers no "newer patch".
#[tokio::test(flavor = "multi_thread")]
async fn a_platform_gems_own_record_is_no_fix_of_its_own() {
    let server = MockServer::start().await;
    let platform_purl = format!("{PURL}?platform={LINUX}");
    let listed = |uuid: &str, purl: &str| {
        json!({
            "uuid": uuid, "purl": purl, "tier": "free", "cveIds": [],
            "ghsaIds": [GHSA], "severity": "high", "title": "platform gem fixture",
        })
    };
    let found = |uuid: &str, purl: &str| {
        json!({
            "uuid": uuid, "purl": purl, "publishedAt": "2026-02-01T00:00:00Z",
            "description": "x", "license": "MIT", "tier": "free",
            "vulnerabilities": { GHSA: {
                "cves": ["CVE-2026-5555"], "summary": "s", "severity": "high",
                "description": "d",
            }},
        })
    };
    // Ahead of `mount_api`'s own answers: the gem's patch and the linux
    // gem's, the latter published later (it would rank first).
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{ "purl": PURL, "patches": [
                listed(UUID, PURL), listed(LINUX_UUID, &platform_purl),
            ]}],
            "canAccessPaidPatches": false,
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [found(LINUX_UUID, &platform_purl), found(UUID, PURL)],
            "canAccessPaidPatches": false,
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();

    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            upstream_event(ARM),
            patched_event("applied", LINUX, LINUX_UUID, true)
        ],
        "the gem is reported per build, and nothing is skipped: {env}"
    );
    let selected: Vec<&Value> = env["packages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|package| package["selectedUuids"].as_array().unwrap())
        .collect();
    assert_eq!(selected, [&json!(UUID)], "{env}");
    let (references, _) = requests(&server).await;
    assert_eq!(references, [[UUID.to_string()]], "one reference request");

    // A later run: in place, and no patch is offered as newer.
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["updates"], json!([]), "{env}");
    assert_eq!(env["rollout"]["counts"]["upgrade"], 0, "{env}");
    assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{env}");

    // `get` for the gem takes the gem's own patch alone, too.
    let fresh = project(&lock(true));
    let (code, stdout, stderr) = hosted(fresh.path(), &api, &["get", PURL], &["--json"]);
    let env: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(
        hosted_events(&env),
        [
            upstream_event(ARM),
            patched_event("applied", LINUX, LINUX_UUID, true)
        ],
        "{env}"
    );
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

// ── VEX ───────────────────────────────────────────────────────────────

const PRODUCT: &str = "pkg:gem/app@1.0.0";
const CVE: &str = "CVE-2026-5555";

/// The path of the index the gem patch's registry serves at snapshot `4`.
fn index_path() -> String {
    format!("/patch-registry/gem/{TOKEN}/{UUID}/s/4/info/{DEP}")
}

fn build_purl(platform: &str) -> String {
    format!("{PURL}?platform={platform}")
}

/// The form Grype and Syft report a platform gem under.
fn grype_form(platform: &str) -> String {
    format!("{PURL}-{platform}")
}

/// What one statement of a document says: its status, the packages of the
/// project it is about, the products it names beside the project, and its
/// impact statement (`not_affected`) or action statement (`affected`).
#[derive(Debug, PartialEq)]
struct Said {
    status: &'static str,
    packages: Vec<String>,
    products: Vec<String>,
    words: String,
}

/// Every statement of `doc`, each about the one vulnerability of the
/// gem patch's record.
fn said(doc: &Value) -> Vec<Said> {
    let ids = |list: &Value, key: &str| -> Vec<String> {
        let items = list.as_array().into_iter().flatten();
        items
            .filter_map(|item| item[key].as_str().map(str::to_string))
            .collect()
    };
    let statements = doc["statements"].as_array().expect("statements");
    statements
        .iter()
        .map(|st| {
            assert_eq!(st["vulnerability"]["name"], GHSA, "{st}");
            assert_eq!(st["vulnerability"]["aliases"], json!([CVE]), "{st}");
            assert_eq!(st["products"][0]["@id"], PRODUCT, "{st}");
            let status = match st["status"].as_str() {
                Some("not_affected") => "not_affected",
                Some("affected") => "affected",
                other => panic!("unexpected status {other:?}: {st}"),
            };
            let words = match status {
                "affected" => &st["action_statement"],
                _ => &st["impact_statement"],
            };
            Said {
                status,
                packages: ids(&st["products"][0]["subcomponents"], "@id"),
                products: ids(&st["products"], "@id")[1..].to_vec(),
                words: words.as_str().unwrap_or_default().to_string(),
            }
        })
        .collect()
}

/// The statement of the builds `platforms`, each patched by the patch
/// beside it; `shared` when every locked build is among them, so that the
/// form Trivy reports the gem under stands for patched builds alone.
fn patched_statement(platforms: &[(&str, &str)], shared: bool) -> Said {
    let mut products: Vec<String> = Vec::new();
    products.extend(shared.then(|| PURL.to_string()));
    products.extend(platforms.iter().map(|(platform, _)| grype_form(platform)));
    products.extend(platforms.iter().map(|(platform, _)| build_purl(platform)));
    let mut parts: Vec<String> = platforms
        .iter()
        .map(|(_, patch)| format!("Patched via Socket patch {patch} (redirected)"))
        .collect();
    parts.sort();
    Said {
        status: "not_affected",
        packages: platforms.iter().map(|(p, _)| build_purl(p)).collect(),
        products,
        words: parts.join("; "),
    }
}

/// The statement of the build for `platform`, which the lock installs as
/// upstream's own gem.
fn upstream_statement(platform: &str) -> Said {
    Said {
        status: "affected",
        packages: vec![build_purl(platform)],
        products: vec![grype_form(platform), build_purl(platform)],
        words: format!(
            "The patch registry has no patched build of this gem for {platform} yet and serves \
             upstream's own gem for it, so an install on that platform is without Socket patch \
             {UUID}. Run `socket-patch scan --mode hosted` again later: the lockfile takes the \
             patched build once it is published."
        ),
    }
}

/// The statement of the build for `platform`, of which nothing shows what
/// the lock installs: `why`, and `remedy` is what to run. It names no
/// patch. `shared` when no locked build is attested, so that the form
/// Trivy reports the gem under stands for affected builds alone.
fn unshown_statement(platform: &str, why: &str, remedy: &str, shared: bool) -> Said {
    let mut products: Vec<String> = Vec::new();
    products.extend(shared.then(|| PURL.to_string()));
    products.extend([grype_form(platform), build_purl(platform)]);
    Said {
        status: "affected",
        packages: vec![build_purl(platform)],
        products,
        words: format!(
            "It could not be shown that the lockfile installs a patched build of this gem for \
             {platform} ({why}), so it is stated as affected. {remedy}"
        ),
    }
}

/// What to run for a build the lock and the patch registry disagree about,
/// and for one a later run can read.
const RESCAN: &str = "Run `socket-patch scan --mode hosted` to bring the lockfile up to date, \
    then `socket-patch vex` again.";
const RETRY: &str = "Run `socket-patch vex` again to attest each build.";

/// The uncounted events of the builds `platforms`, of which nothing shows
/// what the lock installs, after asserting that each says `affected` and
/// that the run counts none of them and is a success.
fn unshown_events(env: &Value, platforms: &[&str]) -> Vec<(String, String, String)> {
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(
        (&env["summary"]["skipped"], &env["summary"]["failed"]),
        (&json!(0), &json!(0)),
        "a build that is not shown patched is counted nowhere: {env}"
    );
    for event in env["events"].as_array().into_iter().flatten() {
        if event["errorCode"] == "vex_gem_build_unknown" {
            assert_eq!(event["details"]["status"], "affected", "{event}");
            assert_eq!(event["uuid"], Value::Null, "no patch is named: {event}");
        }
    }
    platforms
        .iter()
        .map(|platform| event("skipped", platform, "vex_gem_build_unknown"))
        .collect()
}

/// A `--json` hosted scan with `--vex`: exit code, envelope and document.
fn scan_vex(proj: &Path, api: &str) -> (i32, Value, Option<Value>) {
    let out = proj.join("out.vex.json");
    let (code, env) = scan_json(
        proj,
        api,
        &[
            "--vex",
            out.to_str().expect("utf8 temp path"),
            "--vex-product",
            PRODUCT,
            "--patch-server-url",
            api,
        ],
    );
    (code, env, vex_e2e_common::read_doc(&out))
}

/// A later `socket-patch vex` over `proj`, against `api`.
fn vex_run(api: &str) -> vex_e2e_common::VexRun {
    vex_e2e_common::VexRun {
        api_url: Some(api.to_string()),
        api_token: Some(API_TOKEN.to_string()),
        org: Some(ORG.to_string()),
        // The lock's registry is on the mock origin.
        patch_server_url: Some(api.to_string()),
        product: Some(PRODUCT.to_string()),
        ..vex_e2e_common::VexRun::default()
    }
}

fn vex(proj: &Path, api: &str) -> vex_e2e_common::VexOutcome {
    vex_e2e_common::run_vex(&vex_e2e_common::binary(), proj, &vex_run(api))
}

/// A project as a hosted run left it: the gem's two builds on the patch
/// registry `index`, pinned to `arm` and `linux`, or by source alone
/// (`checksums: false`, the lock of a Bundler that writes no `CHECKSUMS`).
fn hosted_project(index: &str, arm: &str, linux: &str, checksums: bool) -> tempfile::TempDir {
    let mut lock = hosted_lock(index, arm, linux);
    if !checksums {
        let at = lock.find("CHECKSUMS\n").expect("a CHECKSUMS section");
        let end = lock.find("BUNDLED WITH").expect("a BUNDLED WITH section");
        lock.replace_range(at..end, "");
    }
    let dir = project(&lock);
    std::fs::write(dir.path().join("Gemfile"), hosted_gemfile(index)).unwrap();
    dir
}

/// The index the patch registry serves at snapshot `4`: the sha256 of
/// each build it lists.
async fn mount_index(server: &MockServer, arm: &str, linux: &str) {
    Mock::given(method("GET"))
        .and(path(index_path()))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "---\n{DEP_VERSION}-{ARM} racc:~> 1.4|checksum:{arm}\n{DEP_VERSION}-{LINUX} racc:~> \
             1.4|checksum:{linux}\n"
        )))
        .mount(server)
        .await;
}

/// How many times the gem patch's record was asked for.
async fn view_requests(server: &MockServer) -> usize {
    let view = format!("/v0/orgs/{ORG}/patches/view/{UUID}");
    let requests = server.received_requests().await.unwrap_or_default();
    requests
        .iter()
        .filter(|request| request.url.path() == view)
        .count()
}

/// The `vex` events of the gem's builds: `(action, purl, errorCode)`,
/// each naming the gem's patch as its fix and its own platform.
fn build_events(env: &Value) -> Vec<(String, String, String)> {
    let events = env["events"].as_array().expect("events");
    events
        .iter()
        .map(|event| {
            let purl = event["purl"].as_str().unwrap_or_default();
            let details = &event["details"];
            assert_eq!(details["gemFix"], UUID, "{event}");
            let platform = details["platform"].as_str().unwrap_or_default();
            assert_eq!(purl, build_purl(platform), "{event}");
            let text = |key: &str| event[key].as_str().unwrap_or_default().to_string();
            (text("action"), text("purl"), text("errorCode"))
        })
        .collect()
}

fn event(action: &str, platform: &str, code: &str) -> (String, String, String) {
    (action.to_string(), build_purl(platform), code.to_string())
}

/// The run's own `--vex`, one locked build patched and one on upstream's
/// gem: the patched build is attested under its own patch, the other is
/// said affected, and neither statement names the gem without a platform
/// (the form a scanner that drops the platform would match both by). No
/// request beyond the run's own: one reference request, one record, and
/// none to the registry. The same holds on a machine whose platform is
/// the one on upstream's gem, with that gem installed.
#[tokio::test(flavor = "multi_thread")]
async fn the_runs_vex_attests_the_patched_build_and_says_affected_of_the_upstream_one() {
    for installed in [false, true] {
        let server = MockServer::start().await;
        mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
        let api = server.uri();
        let proj = project(&lock(true));
        if installed {
            let gem = format!("vendor/bundle/ruby/3.3.0/gems/{DEP}-{DEP_VERSION}-{ARM}/lib");
            std::fs::create_dir_all(proj.path().join(&gem)).unwrap();
            std::fs::write(
                proj.path().join(gem).join("platform_probe.rb"),
                "upstream\n",
            )
            .unwrap();
        }
        let (code, env, doc) = scan_vex(proj.path(), &api);
        assert_eq!(code, 0, "installed: {installed}: {env}");
        assert_eq!(env["status"], "success", "{env}");
        assert_eq!(
            said(&doc.expect("a document")),
            [
                patched_statement(&[(LINUX, LINUX_UUID)], false),
                upstream_statement(ARM)
            ],
            "installed: {installed}"
        );
        assert_eq!(env["vex"]["statements"], 2, "{env}");
        assert_eq!(env["vex"]["affected"], 1, "{env}");
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
        assert_eq!(view_requests(&server).await, 1, "the gem patch's record");
    }
}

/// Every locked build patched: one statement names both builds, each under
/// its own patch, and the gem without a platform too. The gem patch's own
/// uuid is in no statement: no locked build is its ruby-platform gem.
#[tokio::test(flavor = "multi_thread")]
async fn the_runs_vex_attests_every_patched_build_under_its_own_patch() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&BOTH_PATCHED[..], 4))).await;
    let api = server.uri();
    let proj = project(&lock(true));
    let (code, env, doc) = scan_vex(proj.path(), &api);
    assert_eq!(code, 0, "{env}");
    let doc = doc.expect("a document");
    assert_eq!(
        said(&doc),
        [patched_statement(
            &[(ARM, ARM_UUID), (LINUX, LINUX_UUID)],
            true
        )]
    );
    assert!(!doc.to_string().contains(UUID), "{doc}");
    assert_eq!(env["vex"]["statements"], 1, "{env}");
    assert_eq!(env["vex"]["affected"], Value::Null, "{env}");
    let (references, other) = requests(&server).await;
    assert_eq!(references, [[UUID.to_string()]], "one reference request");
    assert_eq!(other, Vec::<String>::new(), "no registry request");
}

/// A lock that names the ruby-platform gem beside the platform builds:
/// that entry is the gem's own patch, attested as the gem itself, beside
/// the patched platform build; the build on upstream's gem is affected.
#[tokio::test(flavor = "multi_thread")]
async fn the_runs_vex_attests_the_ruby_entry_under_the_gems_own_patch() {
    let listing: [Listed; 3] = [
        (ARM, ARM_UPSTREAM, None),
        ("ruby", RUBY_PATCHED, Some(UUID)),
        (LINUX, LINUX_PATCHED, Some(LINUX_UUID)),
    ];
    let server = MockServer::start().await;
    mount_api(&server, Some((&listing[..], 4))).await;
    let api = server.uri();
    let with_ruby = lock(true)
        .replace(
            &format!("    {DEP} ({DEP_VERSION}-{ARM})\n"),
            &format!("    {DEP} ({DEP_VERSION})\n    {DEP} ({DEP_VERSION}-{ARM})\n"),
        )
        .replace(
            &format!("  {DEP} ({DEP_VERSION}-{ARM}) sha256="),
            &format!(
                "  {DEP} ({DEP_VERSION}) sha256={}\n  {DEP} ({DEP_VERSION}-{ARM}) sha256=",
                "d".repeat(64)
            ),
        );
    let proj = project(&with_ruby);
    let (code, env, doc) = scan_vex(proj.path(), &api);
    assert_eq!(code, 0, "{env}");
    let after = read(proj.path(), "Gemfile.lock");
    assert!(
        after.contains(&format!("  {DEP} ({DEP_VERSION}) sha256={RUBY_PATCHED}\n")),
        "{after}"
    );
    let mut patched = patched_statement(&[(LINUX, LINUX_UUID)], false);
    patched.packages.insert(0, PURL.to_string());
    patched.words = format!(
        "Patched via Socket patch {LINUX_UUID} (redirected); Patched via Socket patch {UUID} \
         (redirected)"
    );
    assert_eq!(
        said(&doc.expect("a document")),
        [patched, upstream_statement(ARM)]
    );
    assert_eq!(env["vex"]["affected"], 1, "{env}");
    let (references, other) = requests(&server).await;
    assert_eq!(references, [[UUID.to_string()]], "one reference request");
    assert_eq!(other, Vec::<String>::new(), "no registry request");
}

/// A later `vex` over a lock with `CHECKSUMS`: ONE request beyond the
/// record, the gem patch's reference. The document is the run's own, the
/// envelope reports each build with the gem's patch as its fix, and the
/// build on upstream's gem is neither counted nor a failure. A person
/// reads which builds are attested, with no warning.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_vex_tells_the_builds_of_a_checksummed_lock_apart_in_one_request() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));
    let proj = hosted_project(&index, ARM_UPSTREAM, LINUX_PATCHED, true);

    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(
        said(out.doc()),
        [
            patched_statement(&[(LINUX, LINUX_UUID)], false),
            upstream_statement(ARM)
        ]
    );
    let env = &out.envelope;
    assert_eq!(env["status"], "success", "{out}");
    assert_eq!(
        build_events(env),
        [
            event("verified", LINUX, ""),
            event("skipped", ARM, "gem_upstream_build_kept")
        ],
        "{out}"
    );
    assert_eq!(
        env["events"][1]["reason"],
        format!("the patch registry serves upstream's own gem for {ARM}: no patched build yet"),
        "{out}"
    );
    assert_eq!(env["events"][1]["details"]["status"], "affected", "{out}");
    assert_eq!(
        (&env["summary"]["verified"], &env["summary"]["skipped"]),
        (&json!(1), &json!(0)),
        "the build on upstream's gem is counted nowhere: {out}"
    );
    assert_eq!(warning_codes(env), Vec::<String>::new(), "{out}");
    let (references, other) = requests(&server).await;
    assert_eq!(references, [[UUID.to_string()]], "one reference request");
    assert_eq!(other, Vec::<String>::new(), "no registry request");
    assert_eq!(view_requests(&server).await, 1);

    let human = vex_e2e_common::VexRun {
        human: true,
        ..vex_run(&api)
    };
    let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), proj.path(), &human);
    assert_eq!(out.code, Some(0), "{out}");
    assert!(
        out.stdout.contains(&format!(
            "Wrote OpenVEX document with 2 statements (1 affected) to {}\n{DEP} {DEP_VERSION}: \
             patched for {LINUX}; upstream gem kept for {ARM} (no patched build yet)\n",
            out.output.display()
        )),
        "{out}"
    );
    assert!(!out.stderr.contains("Warning"), "{out}");
}

/// A later `vex` over a lock with no `CHECKSUMS`: the lock installs what
/// its own registry serves, so a SECOND request reads that registry's
/// index. Two requests, the same document. With the index unreadable
/// nothing shows what the lock installs: both builds are in the document
/// as affected, the run exits 0 as a success, and one warning says why
/// (with the error of the read) and what to run.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_vex_asks_the_registry_of_a_lock_without_checksums() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    mount_index(&server, ARM_UPSTREAM, LINUX_PATCHED).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));
    let proj = hosted_project(&index, ARM_UPSTREAM, LINUX_PATCHED, false);
    assert!(!read(proj.path(), "Gemfile.lock").contains("CHECKSUMS"));

    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(
        said(out.doc()),
        [
            patched_statement(&[(LINUX, LINUX_UUID)], false),
            upstream_statement(ARM)
        ]
    );
    assert_eq!(out.envelope["status"], "success", "{out}");
    let (references, other) = requests(&server).await;
    assert_eq!(references, [[UUID.to_string()]], "one reference request");
    assert_eq!(other, [index_path()], "and the lock's own registry, once");

    // No index to read: nothing says what the lock installs.
    let silent = MockServer::start().await;
    mount_api(&silent, Some((&ONE_PATCHED[..], 4))).await;
    let api = silent.uri();
    let index = format!("{}/", index_url(&api, Some(4)));
    let proj = hosted_project(&index, ARM_UPSTREAM, LINUX_PATCHED, false);
    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    let why = "the lockfile has no CHECKSUMS entry for it, and its registry's index could not be \
               read";
    assert_eq!(
        said(out.doc()),
        [
            unshown_statement(ARM, why, RETRY, true),
            unshown_statement(LINUX, why, RETRY, true)
        ],
        "{out}"
    );
    assert!(
        !out.doc().to_string().contains(LINUX_UUID) && !out.doc().to_string().contains(UUID),
        "no patch is named for a build that is not shown patched: {out}"
    );
    assert_eq!(
        build_events(&out.envelope),
        unshown_events(&out.envelope, &[ARM, LINUX]),
        "{out}"
    );
    assert_eq!(
        out.envelope["events"][0]["reason"],
        format!("not shown patched for {ARM}: {why}"),
        "{out}"
    );
    assert_eq!(
        warning_codes(&out.envelope),
        ["vex_gem_build_unknown"],
        "{out}"
    );
    let detail = out.envelope["warnings"][0]["detail"].as_str().unwrap();
    assert!(
        detail.contains(
            "(the lockfile has no CHECKSUMS entry for them, and its registry's index could not \
             be read: "
        ) && detail.ends_with(&format!(
            "), so the VEX document states them as affected. {RETRY}"
        )) && !detail.contains(TOKEN),
        "{detail}"
    );
}

/// The reference a later `vex` gets is of a newer registry than the lock
/// names: it lists a patched build for the platform the lock still pins
/// upstream's gem for. That build is NOT attested: the lock does not
/// install it. It is in the document as affected, with no patch named for
/// it, beside the build the lock does pin patched; the run exits 0 as a
/// success and sends the reader to the scan that moves the lock.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_vex_says_affected_of_a_build_a_newer_reference_lists_but_the_lock_does_not_pin() {
    for checksums in [true, false] {
        let server = MockServer::start().await;
        mount_api(&server, Some((&BOTH_PATCHED[..], 5))).await;
        // The registry the lock names still serves upstream's gem there.
        mount_index(&server, ARM_UPSTREAM, LINUX_PATCHED).await;
        let api = server.uri();
        let index = format!("{}/", index_url(&api, Some(4)));
        let proj = hosted_project(&index, ARM_UPSTREAM, LINUX_PATCHED, checksums);

        let why = "the lockfile installs another archive for it than the patch registry lists now";
        let out = vex(proj.path(), &api);
        assert_eq!(out.code, Some(0), "checksums: {checksums}: {out}");
        assert_eq!(
            said(out.doc()),
            [
                patched_statement(&[(LINUX, LINUX_UUID)], false),
                unshown_statement(ARM, why, RESCAN, false)
            ],
            "checksums: {checksums}"
        );
        assert!(!out.doc().to_string().contains(ARM_UUID), "{out}");
        let mut events = vec![event("verified", LINUX, "")];
        events.extend(unshown_events(&out.envelope, &[ARM]));
        assert_eq!(build_events(&out.envelope), events, "{out}");
        assert_eq!(
            out.envelope["events"][1]["reason"],
            format!("not shown patched for {ARM}: {why}"),
            "{out}"
        );
        assert_eq!(out.envelope["summary"]["verified"], 1, "{out}");
        assert_eq!(
            warning_codes(&out.envelope),
            ["vex_gem_build_unknown"],
            "{out}"
        );
        assert_eq!(
            out.envelope["warnings"][0]["detail"],
            format!(
                "{PURL}: the lockfile takes its build for {ARM} from the registry of Socket patch \
                 {UUID}, which serves a patched build for some platforms and upstream's own gem \
                 for the others. Which it is for this one could not be told (the lockfile \
                 installs another archive for it than the patch registry lists now), so the VEX \
                 document states it as affected. {RESCAN}"
            ),
            "{out}"
        );
        let (references, other) = requests(&server).await;
        assert_eq!(references, [[UUID.to_string()]], "one reference request");
        assert_eq!(other.len(), usize::from(!checksums), "{other:?}");

        // A person reads the warning and what the document says of each
        // build: nothing is left out, and nothing fails.
        let human = vex_e2e_common::VexRun {
            human: true,
            ..vex_run(&api)
        };
        let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), proj.path(), &human);
        assert_eq!(out.code, Some(0), "{out}");
        assert!(
            out.stdout.ends_with(&format!(
                "Wrote OpenVEX document with 2 statements (1 affected) to {}\n{DEP} \
                 {DEP_VERSION}: patched for {LINUX}; not shown patched for {ARM}\n",
                out.output.display()
            )),
            "{out}"
        );
        assert!(
            out.stderr.contains(&format!(
                "Warning: {PURL}: the lockfile takes its build for {ARM} from the registry of \
                 Socket patch {UUID}"
            )),
            "{out}"
        );
        assert!(
            out.stderr.matches("Warning: ").count() == 1
                && !out.stderr.contains("omitting")
                && !out.stderr.contains("Error"),
            "one warning, and nothing left out: {out}"
        );

        // The scan the note names moves the lock, and the next document
        // attests both builds.
        let (code, env, doc) = scan_vex(proj.path(), &api);
        assert_eq!(code, 0, "{env}");
        assert_eq!(
            said(&doc.expect("a document")),
            [patched_statement(
                &[(ARM, ARM_UUID), (LINUX, LINUX_UUID)],
                true
            )]
        );
    }
}

/// A hosted run's own `--vex` can meet a build it cannot tell too: a gem
/// an earlier run moved, whose patch this run's search does not return
/// (such a pin is kept, and the run pins nothing), on a lock older than
/// the reference lists. The run's document says `affected` of that build
/// beside the one the lock pins patched, the warning is among the
/// document's, and the run is a success. With every build untold it still
/// is: both are in the document as affected.
#[tokio::test(flavor = "multi_thread")]
async fn the_runs_vex_says_affected_of_a_build_of_a_gem_it_did_not_pin() {
    let why = "the lockfile installs another archive for it than the patch registry lists now";
    for (linux_pin, statements, affected) in [
        (
            LINUX_PATCHED,
            vec![
                patched_statement(&[(LINUX, LINUX_UUID)], false),
                unshown_statement(ARM, why, RESCAN, false),
            ],
            1,
        ),
        (
            LINUX_UPSTREAM,
            vec![
                unshown_statement(ARM, why, RESCAN, true),
                unshown_statement(LINUX, why, RESCAN, true),
            ],
            2,
        ),
    ] {
        let server = MockServer::start().await;
        // The search finds no patch for the gem.
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "packages": [], "canAccessPaidPatches": false,
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        mount_api(&server, Some((&BOTH_PATCHED[..], 5))).await;
        let api = server.uri();
        let index = format!("{}/", index_url(&api, Some(4)));
        let proj = hosted_project(&index, ARM_UPSTREAM, linux_pin, true);
        let before = read(proj.path(), "Gemfile.lock");
        let (code, env, doc) = scan_vex(proj.path(), &api);
        assert_eq!(code, 0, "{env}");
        assert_eq!(env["status"], "success", "{env}");
        assert_eq!(hosted_events(&env), Vec::<Value>::new(), "{env}");
        assert_eq!(
            read(proj.path(), "Gemfile.lock"),
            before,
            "nothing is pinned"
        );
        assert_eq!(said(&doc.expect("a document")), statements, "{env}");
        assert_eq!(env["vex"]["statements"], 2, "{env}");
        assert_eq!(env["vex"]["affected"], affected, "{env}");
        let vex_warnings: Vec<&str> = env["vex"]["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|warning| warning["code"].as_str())
            .collect();
        assert_eq!(
            vex_warnings,
            ["vex_hosted_unverified", "vex_gem_build_unknown"],
            "the standing note of a hosted run's document, and the one warning for the gem: {env}"
        );
    }
}

/// The record of the gem's patch as a pre-v5 hosted ledger holds it: the
/// one way a hosted pin has a record with no request.
fn write_record_ledger(proj: &Path) {
    let view = json!({
        "uuid": UUID,
        "files": { "lib/platform_probe.rb": {
            "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64),
        }},
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "s", "severity": "high", "description": "d",
        }},
        "description": "x", "license": "MIT", "tier": "free",
    });
    vex_e2e_common::write_legacy_redirect_ledger(proj, PURL, &view);
}

/// `--offline`, with the record of the gem's patch at hand: no request at
/// all, so nothing says which locked build is patched. The gem's one pin
/// would have attested every build; instead each platform build is in the
/// document as affected, the run exits 0 as a success, and one warning
/// names the gem and what to run.
#[tokio::test(flavor = "multi_thread")]
async fn an_offline_vex_says_affected_of_each_platform_build_and_warns_once() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));
    let proj = hosted_project(&index, ARM_UPSTREAM, LINUX_PATCHED, true);
    write_record_ledger(proj.path());
    let offline = vex_e2e_common::VexRun {
        offline: true,
        ..vex_run(&api)
    };

    let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), proj.path(), &offline);
    assert_eq!(out.code, Some(0), "{out}");
    let (why, online) = (
        "--offline forbids asking the patch API",
        "Run `socket-patch vex` without --offline to attest each build.",
    );
    assert_eq!(
        said(out.doc()),
        [
            unshown_statement(ARM, why, online, true),
            unshown_statement(LINUX, why, online, true)
        ],
        "{out}"
    );
    assert!(
        !out.doc().to_string().contains(LINUX_UUID) && !out.doc().to_string().contains(UUID),
        "no patch is named for a build that is not shown patched: {out}"
    );
    assert_eq!(
        build_events(&out.envelope),
        unshown_events(&out.envelope, &[ARM, LINUX]),
        "{out}"
    );
    assert_eq!(
        out.envelope["warnings"],
        json!([{
            "code": "vex_gem_build_unknown",
            "detail": format!(
                "{PURL}: the lockfile takes its builds for {ARM}, {LINUX} from the registry of \
                 Socket patch {UUID}, which serves a patched build for some platforms and \
                 upstream's own gem for the others. Which it is for these could not be told \
                 (--offline forbids asking the patch API), so the VEX document states them as \
                 affected. {online}"
            ),
        }]),
        "{out}"
    );
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        0,
        "--offline asks nothing"
    );

    // Online, the same project is the document of the run that moved it.
    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(
        said(out.doc()),
        [
            patched_statement(&[(LINUX, LINUX_UUID)], false),
            upstream_statement(ARM)
        ]
    );
    assert_eq!(view_requests(&server).await, 0, "the ledger has the record");
}

/// The reference request fails: the record is there, the list of the
/// gem's builds is not. No build is attested as patched: each is in the
/// document as affected, the run exits 0 as a success, the registry is
/// not asked, and the warning carries the failure (the document does not).
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_reference_request_says_affected_of_each_platform_build() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&server)
        .await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));
    let proj = hosted_project(&index, ARM_UPSTREAM, LINUX_PATCHED, true);

    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    let why = "the patch API request failed";
    assert_eq!(
        said(out.doc()),
        [
            unshown_statement(ARM, why, RETRY, true),
            unshown_statement(LINUX, why, RETRY, true)
        ],
        "{out}"
    );
    assert_eq!(
        build_events(&out.envelope),
        unshown_events(&out.envelope, &[ARM, LINUX]),
        "{out}"
    );
    assert_eq!(
        warning_codes(&out.envelope),
        ["vex_gem_build_unknown"],
        "{out}"
    );
    let detail = out.envelope["warnings"][0]["detail"].as_str().unwrap();
    assert!(
        detail.contains("could not be told (the patch API request failed: ")
            && detail.ends_with(&format!(
                "), so the VEX document states them as affected. {RETRY}"
            )),
        "{detail}"
    );
    let (references, other) = requests(&server).await;
    assert!(
        !references.is_empty() && references.iter().all(|asked| asked == &[UUID.to_string()]),
        "{references:?}"
    );
    assert_eq!(other, Vec::<String>::new(), "no registry request");

    // A person reads one warning for the gem and one line for its builds,
    // each named with its platform, and no error.
    let human = vex_e2e_common::VexRun {
        human: true,
        ..vex_run(&api)
    };
    let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), proj.path(), &human);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(out.stderr.matches("Warning: ").count(), 1, "{out}");
    assert!(
        out.stderr.contains(&format!(
            "Warning: {PURL}: the lockfile takes its builds for {ARM}, {LINUX} from the \
             registry of Socket patch {UUID}"
        )) && !out.stderr.contains("omitting")
            && !out.stderr.contains("Error"),
        "{out}"
    );
    assert!(
        out.stdout.ends_with(&format!(
            "Wrote OpenVEX document with 2 statements (2 affected) to {}\n{DEP} {DEP_VERSION}: \
             not shown patched for {ARM}, {LINUX}\n",
            out.output.display()
        )),
        "{out}"
    );
}

/// A gem locked as its ruby-platform gem alone is the one pin it always
/// was: attested as the gem under the gem's patch, with the record as the
/// only request. No reference is asked for and no registry is read.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_vex_of_a_gem_locked_as_its_ruby_gem_alone_asks_nothing_new() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let api = server.uri();
    let index = index_url(&api, None);
    let lock = format!(
        "GEM\n  remote: {index}\n  specs:\n    {DEP} ({DEP_VERSION})\n\nGEM\n  remote: \
         https://rubygems.org/\n  specs:\n    racc (1.8.1)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  \
         {DEP} (= {DEP_VERSION})!\n  racc (= 1.8.1)\n\nCHECKSUMS\n  {DEP} ({DEP_VERSION}) \
         sha256={RUBY_PATCHED}\n  racc (1.8.1) sha256={RACC}\n\nBUNDLED WITH\n  4.0.15\n"
    );
    let proj = project(&lock);
    std::fs::write(proj.path().join("Gemfile"), hosted_gemfile(&index)).unwrap();

    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(
        said(out.doc()),
        [Said {
            status: "not_affected",
            packages: vec![PURL.to_string()],
            products: vec![PURL.to_string()],
            words: format!("Patched via Socket patch {UUID} (redirected)"),
        }]
    );
    assert_eq!(
        out.envelope["events"],
        json!([{
            "action": "verified", "purl": PURL,
            "details": { "vulnerability": GHSA, "aliases": [CVE], "status": "not_affected" },
        }]),
        "{out}"
    );
    let (references, other) = requests(&server).await;
    assert_eq!(
        references,
        Vec::<Vec<String>>::new(),
        "no reference request"
    );
    assert_eq!(other, Vec::<String>::new(), "no registry request");
    assert_eq!(
        server.received_requests().await.unwrap_or_default().len(),
        1,
        "the record, and nothing else"
    );
}

/// Installed copies are judged per build. A machine of the platform on
/// upstream's gem holds upstream's gem, as its lock entry names it: that
/// copy is no evidence against the build the lock installs patched. A copy
/// of that patched build is: one that does not hold the patch withholds
/// it, and the build on upstream's gem is affected either way.
#[tokio::test(flavor = "multi_thread")]
async fn an_installed_copy_is_evidence_about_its_own_build_alone() {
    let patched = b"module PlatformProbe\n  FIXED = true\nend\n";
    let upstream = b"module PlatformProbe\n  FIXED = false\nend\n";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "lib/platform_probe.rb": {
                "beforeHash": vex_e2e_common::git_sha256(upstream),
                "afterHash": vex_e2e_common::git_sha256(patched),
            }},
            "vulnerabilities": { GHSA: {
                "cves": [CVE], "summary": "s", "severity": "high", "description": "d",
            }},
            "description": "x", "license": "MIT", "tier": "free",
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));
    let proj = hosted_project(&index, ARM_UPSTREAM, LINUX_PATCHED, true);
    let install = |platform: &str, content: &[u8]| {
        let lib = proj.path().join(format!(
            "vendor/bundle/ruby/3.3.0/gems/{DEP}-{DEP_VERSION}-{platform}/lib"
        ));
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(lib.join("platform_probe.rb"), content).unwrap();
    };
    let both = [
        patched_statement(&[(LINUX, LINUX_UUID)], false),
        upstream_statement(ARM),
    ];

    // This machine's platform is the one on upstream's gem.
    install(ARM, upstream);
    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(said(out.doc()), both, "{out}");
    assert_eq!(out.envelope["status"], "success", "{out}");

    // The patched build installed beside it, holding the patch.
    install(LINUX, patched);
    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(said(out.doc()), both, "{out}");

    // That copy still on upstream's files: the build is not attested, and
    // no build of the gem is, so the gem without a platform is affected.
    install(LINUX, upstream);
    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    let mut unpatched = upstream_statement(ARM);
    unpatched.products.insert(0, PURL.to_string());
    assert_eq!(said(out.doc()), [unpatched], "{out}");
    vex_e2e_common::assert_not_attested(&out.envelope, PURL, "not_applied");
    assert_eq!(out.envelope["status"], "partialFailure", "{out}");
}
