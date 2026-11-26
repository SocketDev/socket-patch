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
//!   patched. A lock with `CHECKSUMS` says what each build was; one
//!   without is told by the snapshot it names, in one request;
//! * a platform the registry does not list leaves the gem alone under a
//!   quiet skip, and a reference with no list at all under the warning
//!   `redirect_gem_platform_unsupported`;
//! * a lock whose patched build was withdrawn follows the list back to
//!   upstream's gem, and is then counted as no package on a hosted patch;
//! * a lock on the registry of another patch of the gem moves to the patch
//!   on offer only when no locked build would turn from a patched build
//!   that registry still serves into upstream's gem, which one request to
//!   the registry it is on says; otherwise it stays, under a quiet skip. A
//!   build that registry withdrew holds nothing back: the lock moves, and
//!   the run says that the build is back on upstream's gem;
//! * a lock that stays on another patch of the gem, while that patch has
//!   withdrawn a build the lock pins, is brought to that patch's current
//!   listing: the run takes that patch's reference (the one its check of
//!   the pins holds, else one request), writes its current snapshot with
//!   upstream's sha256 back for the withdrawn build, and skips the patch
//!   on offer as before;
//! * a gem the lock names as its ruby-platform gem alone takes the
//!   registry without its snapshot level, so a pair pinned by a reference
//!   with no list is left byte for byte by one with a list.
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
#[path = "common/pty_io.rs"]
mod pty_io;
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
    registry_url(api, UUID, snapshot)
}

/// [`index_url`] of the gem patch `uuid`.
fn registry_url(api: &str, uuid: &str, snapshot: Option<u32>) -> String {
    let root = format!("{api}/patch-registry/gem/{TOKEN}/{uuid}/");
    match snapshot {
        Some(snapshot) => format!("{root}s/{snapshot}"),
        None => root,
    }
}

/// The reference of the gem patch `uuid` on `api`. `listing` is its
/// `gemBuilds` and the snapshot its registry URL names; `None` is a
/// reference with no list (a patch of the ruby gem alone).
fn reference(api: &str, uuid: &str, listing: Option<(&[Listed], u32)>) -> Value {
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
    let artifact =
        format!("{api}/patch/gem/{DEP}/{DEP_VERSION}/{TOKEN}/{uuid}/{DEP}-{DEP_VERSION}.gem");
    json!({
        "status": "granted",
        "url": artifact,
        "purl": PURL,
        "artifacts": [{
            "kind": "tarball", "url": artifact,
            "integrity": { "sha256": RUBY_PATCHED },
        }],
        "registryOverride": {
            "kind": "rubygems-compact-index",
            "indexUrl": registry_url(api, uuid, listing.map(|(_, snapshot)| snapshot)),
            "identifiers": identifiers,
        },
    })
}

/// Mount the patch API of the one gem patch, with [`reference`] of
/// `listing` as its reference.
async fn mount_api(server: &MockServer, listing: Option<(&[Listed], u32)>) {
    let api = server.uri();
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
            "results": { UUID: reference(&api, UUID, listing) }
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

/// A locked platform the list leaves out: a machine of that platform
/// would be sent to a registry with no gem for it, so the gem is left as
/// it is, with no warning and one plain line that says only that the
/// registry does not list the platform. A later run over a list that has
/// the platform moves it.
#[tokio::test(flavor = "multi_thread")]
async fn a_platform_missing_from_the_list_leaves_the_gem_as_it_is_quietly() {
    let linux_only: [Listed; 1] = [(LINUX, LINUX_PATCHED, Some(LINUX_UUID))];
    let server = MockServer::start().await;
    mount_api(&server, Some((&linux_only[..], 4))).await;
    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock(true));
    assert_eq!(read(proj.path(), "Gemfile"), GEMFILE);
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    let unlisted = format!(
        "{DEP} {DEP_VERSION}: the patch registry does not list {ARM}, so the gem is left as it is"
    );
    assert_eq!(
        hosted_events(&env),
        [json!({
            "action": "skipped", "purl": PURL, "uuid": UUID,
            "errorCode": "redirect_gem_platform_unlisted",
            "reason": unlisted,
            "details": { "mode": "hosted" },
        })],
        "{env}"
    );
    assert_eq!(env["summary"]["failed"], 0, "{env}");

    let (code, stdout, stderr) = hosted(proj.path(), &server.uri(), &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains(&format!("\n{unlisted}\n")), "{stdout}");
    assert!(!stderr.contains("Warning"), "{stderr}");

    // The list names the platform: the gem moves.
    let later = MockServer::start().await;
    mount_api(&later, Some((&ONE_PATCHED[..], 5))).await;
    let (code, env) = scan_json(proj.path(), &later.uri(), &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert_ne!(read(proj.path(), "Gemfile.lock"), lock(true));
}

/// Mount the searches of the patch API under `routes` (the organisation's
/// `/v0/orgs/<org>/patches`, or the public proxy's `/patch`), ahead of
/// [`mount_api`]'s own answers: each finds the gem's patch and the patch
/// record of its linux gem, the latter published later (it would rank
/// first).
async fn mount_searches_with_a_platform_gems_record(server: &MockServer, routes: &str) {
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
    Mock::given(method("POST"))
        .and(path(format!("{routes}/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{ "purl": PURL, "patches": [
                listed(UUID, PURL), listed(LINUX_UUID, &platform_purl),
            ]}],
            "canAccessPaidPatches": false,
        })))
        .with_priority(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!("^{routes}/by-package/.+$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [found(LINUX_UUID, &platform_purl), found(UUID, PURL)],
            "canAccessPaidPatches": false,
        })))
        .with_priority(1)
        .mount(server)
        .await;
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
    mount_searches_with_a_platform_gems_record(&server, &format!("/v0/orgs/{ORG}/patches")).await;
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

/// The run's client is where the platform gem's record is left out, so
/// what it remembers and the client it falls back to leave it out too.
/// A scan of two project directories asks the patch service once for both
/// and answers the second from memory: each directory moves through the
/// gem's own patch. And a run the API refuses (401) goes on with the
/// public proxy, whose searches find the same record: the outcome is the
/// one of the organisation's route.
#[tokio::test(flavor = "multi_thread")]
async fn a_platform_gems_own_record_is_no_fix_from_memory_or_on_the_public_proxy() {
    // Two project directories, one run.
    let server = MockServer::start().await;
    mount_searches_with_a_platform_gems_record(&server, &format!("/v0/orgs/{ORG}/patches")).await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(4)));
    let root = tempfile::tempdir().unwrap();
    for dir in ["a", "b"] {
        std::fs::create_dir(root.path().join(dir)).unwrap();
        std::fs::write(root.path().join(dir).join("Gemfile"), GEMFILE).unwrap();
        std::fs::write(root.path().join(dir).join("Gemfile.lock"), lock(true)).unwrap();
    }
    let (code, stdout, stderr) = hosted(root.path(), &api, &["scan", "a", "b"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    for dir in ["a", "b"] {
        assert_eq!(
            read(&root.path().join(dir), "Gemfile.lock"),
            hosted_lock(&index, ARM_UPSTREAM, LINUX_PATCHED),
            "{dir}:\n{stdout}\n{stderr}"
        );
    }
    assert!(!stderr.contains("Warning"), "{stderr}");
    let (references, _) = requests(&server).await;
    assert_eq!(
        references,
        [[UUID.to_string()], [UUID.to_string()]],
        "one reference request a directory, for the gem's patch alone"
    );
    let searches = server.received_requests().await.unwrap_or_default();
    let searched = |route: &str| {
        let paths = searches.iter().map(|request| request.url.path());
        paths.filter(|path| path.contains(route)).count()
    };
    // (Where file descriptors are scarce a run asks directory by directory.)
    if !socket_patch_core::crawlers::walk_pool::fd_limit_is_tight() {
        assert_eq!(
            (searched("/patches/batch"), searched("/patches/by-package/")),
            (1, 1),
            "premise: the second directory is answered from memory"
        );
    }

    // The API refuses the token: the run goes on with the public proxy.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": { "message": "Unauthorized" },
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    mount_searches_with_a_platform_gems_record(&server, "/patch").await;
    let api = server.uri();
    Mock::given(method("POST"))
        .and(path("/patch/package"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { UUID: reference(&api, UUID, Some((&ONE_PATCHED[..], 4))) }
        })))
        .mount(&server)
        .await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &api, &["--proxy-url", api.as_str()]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            upstream_event(ARM),
            patched_event("applied", LINUX, LINUX_UUID, true)
        ],
        "{env}"
    );
    let selected: Vec<&Value> = env["packages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|package| package["selectedUuids"].as_array().unwrap())
        .collect();
    assert_eq!(selected, [&json!(UUID)], "{env}");
    let asked = server.received_requests().await.unwrap_or_default();
    let on_proxy: Vec<&str> = asked
        .iter()
        .map(|request| request.url.path())
        .filter(|path| path.starts_with("/patch/"))
        .collect();
    assert!(
        on_proxy.contains(&"/patch/batch") && on_proxy.iter().any(|p| p.contains("/by-package/")),
        "premise: the searches ran on the public proxy: {on_proxy:?}"
    );
    let referenced: Vec<Value> = asked
        .iter()
        .filter(|request| request.url.path() == "/patch/package")
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).unwrap_or_default()["uuids"].clone()
        })
        .collect();
    assert_eq!(referenced, [json!([UUID])], "one reference request");
}

/// The one patched build a lock pins is withdrawn: the list has upstream's
/// gem for every locked platform. The lock follows it (the registry under
/// the earlier snapshot refuses that build from then on), and from there
/// on the gem installs nothing patched. So it is no package on a hosted
/// patch: no `applied` event, the summary line counts none, and no row
/// under it calls the gem patched; the line of the gem says what is true,
/// on the run that follows the withdrawal that the build is back on
/// upstream's gem, and from then on that both builds are upstream's.
#[tokio::test(flavor = "multi_thread")]
async fn a_gem_whose_builds_are_all_upstreams_is_no_package_on_a_hosted_patch() {
    let server = MockServer::start().await;
    mount_api(&server, Some((&ONE_PATCHED[..], 4))).await;
    let proj = project(&lock(true));
    let (code, env) = scan_json(proj.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["summary"]["applied"], 1, "premise: {env}");

    // The same registry, as it stands after the withdrawal.
    server.reset().await;
    mount_api(&server, Some((&NONE_PATCHED[..], 5))).await;
    let api = server.uri();
    let index = format!("{}/", index_url(&api, Some(5)));
    // The run that follows the withdrawal, over a copy of the pair: the
    // build is reported as back on upstream's gem, counted nowhere, and
    // the lock's own registry is not asked what it lists.
    let before = format!("{}/", index_url(&api, Some(4)));
    let copy = hosted_project(&before, ARM_UPSTREAM, LINUX_PATCHED, true);
    assert_eq!(
        read(copy.path(), "Gemfile.lock"),
        read(proj.path(), "Gemfile.lock"),
        "premise: the pair the first run left"
    );
    let (code, env) = scan_json(copy.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [upstream_event(ARM), withdrawn_event(LINUX)],
        "{env}"
    );
    let summary = &env["summary"];
    assert_eq!(
        (&summary["applied"], &summary["skipped"], &summary["failed"]),
        (&json!(0), &json!(0), &json!(0)),
        "{env}"
    );
    assert_eq!(
        read(copy.path(), "Gemfile.lock"),
        hosted_lock(&index, ARM_UPSTREAM, LINUX_UPSTREAM)
    );
    let (_, other) = requests(&server).await;
    assert_eq!(other, Vec::<String>::new(), "no registry request");
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&index, ARM_UPSTREAM, LINUX_UPSTREAM),
        "the lock follows the list back to upstream's gem"
    );
    assert!(
        stdout.contains("Switched 0 packages to hosted patches; rewrote 2 files.\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("already on hosted patches"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: upstream gem back for {LINUX} (its patched build was \
             withdrawn); upstream gem kept for {ARM} (no patched build yet)\n"
        )),
        "{stdout}"
    );
    assert!(
        !stdout.contains(&format!("{DEP}@{DEP_VERSION}  {GHSA}")),
        "no row calls the gem patched:\n{stdout}"
    );
    assert!(!stdout.contains("Nothing left to patch."), "{stdout}");

    // In place afterwards: still nothing in effect, nothing rewritten.
    let (code, env) = scan_json(proj.path(), &api, &[]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["summary"]["applied"], 0, "{env}");
    assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{env}");
    assert_eq!(
        hosted_events(&env),
        [upstream_event(ARM), upstream_event(LINUX)],
        "{env}"
    );
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(!stdout.contains("already on hosted patches"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: upstream gem kept for {ARM}, {LINUX} (no patched build yet)\n"
        )),
        "{stdout}"
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

// ── A lock on the registry of another patch of the gem ────────────────

/// An earlier patch of the gem, which the lock of these tests is on while
/// the patch service offers [`UUID`] for it.
const EARLIER_UUID: &str = "9c8b7a6f-5e4d-4c3b-8a29-1f0e9d8c7b6a";
/// The patch of the earlier patch's patched `x86_64-linux-gnu` build, and
/// the sha256 of that build.
const EARLIER_LINUX_UUID: &str = "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f";
const EARLIER_LINUX_PATCHED: &str =
    "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
/// What the earlier patch's reference lists, at snapshot `3`.
const EARLIER_BUILDS: [Listed; 2] = [
    (ARM, ARM_UPSTREAM, None),
    (LINUX, EARLIER_LINUX_PATCHED, Some(EARLIER_LINUX_UUID)),
];
/// A patch with a patched build for `arm64-darwin` alone.
const ARM_ONLY: [Listed; 2] = [
    (ARM, ARM_PATCHED, Some(ARM_UUID)),
    (LINUX, LINUX_UPSTREAM, None),
];

/// The registry of the earlier patch on `origin`, as a lock names it.
fn earlier_index(origin: &str) -> String {
    format!("{}/", registry_url(origin, EARLIER_UUID, Some(3)))
}

/// [`mount_api`] for the patch on offer, whose reference lists `offered`
/// at snapshot `4`, with the earlier patch's reference granted beside it:
/// the lock's pin is a patch the service still serves.
async fn mount_api_beside_earlier(server: &MockServer, offered: &[Listed]) {
    let api = server.uri();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": {
                UUID: reference(&api, UUID, Some((offered, 4))),
                EARLIER_UUID: reference(&api, EARLIER_UUID, Some((&EARLIER_BUILDS[..], 3))),
            }
        })))
        .with_priority(1)
        .mount(server)
        .await;
    mount_api(server, Some((offered, 4))).await;
}

/// The compact-index document of the earlier patch's registry, listing
/// `linux` as the sha256 of its `x86_64-linux-gnu` gem.
async fn mount_earlier_index(server: &MockServer, linux: &str) {
    mount_earlier_listing(server, Some(linux)).await;
}

/// The compact-index document of the earlier patch's registry: the patched
/// ruby gem, upstream's `arm64-darwin` gem, and the `x86_64-linux-gnu` gem
/// under the sha256 `linux` (`None`: that build was withdrawn, and the
/// registry does not list it).
async fn mount_earlier_listing(server: &MockServer, linux: Option<&str>) {
    let mut listing = format!(
        "---\n{DEP_VERSION} racc:~> 1.4|checksum:{RUBY_PATCHED}\n{DEP_VERSION}-{ARM} racc:~> \
         1.4|checksum:{ARM_UPSTREAM}\n"
    );
    if let Some(linux) = linux {
        listing.push_str(&format!(
            "{DEP_VERSION}-{LINUX} racc:~> 1.4|checksum:{linux}\n"
        ));
    }
    Mock::given(method("GET"))
        .and(path(earlier_index_path()))
        .respond_with(ResponseTemplate::new(200).set_body_string(listing))
        .mount(server)
        .await;
}

fn earlier_index_path() -> String {
    format!("/patch-registry/gem/{TOKEN}/{EARLIER_UUID}/s/3/info/{DEP}")
}

/// The quiet skip of the patch on offer, left for a later run because the
/// lock would lose its patched `x86_64-linux-gnu` build.
fn newer_fix_waits() -> (String, Value) {
    let line = format!(
        "{DEP} {DEP_VERSION}: the newer fix has no patched build for {LINUX} yet; the lock stays \
         on the patch it is on"
    );
    let event = json!({
        "action": "skipped", "purl": PURL, "uuid": UUID,
        "errorCode": "redirect_gem_newer_fix_waits", "reason": line,
        "details": { "mode": "hosted" },
    });
    (line, event)
}

/// The lock is on an earlier patch of the gem, with a patched build for
/// `x86_64-linux-gnu`. The patch on offer has a patched build for
/// `arm64-darwin` alone: moving the lock would turn the linux build into
/// upstream's gem. The lock's `CHECKSUMS` say what it pins, and its
/// registry, asked once a run, that it still serves that build: both files
/// stay byte for byte, with no warning, one skipped event under the quiet
/// code and one plain line.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_on_an_earlier_patch_keeps_its_patched_build_and_waits_quietly() {
    let server = MockServer::start().await;
    mount_api_beside_earlier(&server, &ARM_ONLY[..]).await;
    mount_earlier_index(&server, EARLIER_LINUX_PATCHED).await;
    let api = server.uri();
    let earlier = earlier_index(&api);
    let (lock, gemfile) = (
        hosted_lock(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED),
        hosted_gemfile(&earlier),
    );
    let (line, event) = newer_fix_waits();
    let known = ["--patch-server-url", api.as_str()];

    for dry_run in [false, true] {
        let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
        let mut extra = known.to_vec();
        extra.extend(dry_run.then_some("--dry-run"));
        let (code, env) = scan_json(proj.path(), &api, &extra);
        assert_eq!(code, 0, "{env}");
        assert_eq!(env["status"], "success", "{env}");
        assert_eq!(read(proj.path(), "Gemfile.lock"), lock);
        assert_eq!(read(proj.path(), "Gemfile"), gemfile);
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        assert_eq!(hosted_events(&env), [event.clone()], "{env}");
        let summary = &env["summary"];
        assert_eq!(
            (&summary["applied"], &summary["skipped"], &summary["failed"]),
            (&json!(0), &json!(1), &json!(0)),
            "{env}"
        );
        assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{env}");
        let (_, other) = requests(&server).await;
        assert_eq!(
            other,
            vec![earlier_index_path(); if dry_run { 2 } else { 1 }],
            "one request a run, to the registry the lock is on"
        );
    }

    // For a person: the one line on stdout, and nothing that warns.
    let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &known);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains(&format!("\n{line}\n")), "{stdout}");
    assert!(
        !stderr.contains("No patches could be switched")
            && !stderr.contains("Warning")
            && !stderr.contains("Not hosted")
            && !stderr.contains(DEP),
        "nothing on stderr names it:\n{stderr}"
    );
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock);
    assert_eq!(read(proj.path(), "Gemfile"), gemfile);

    // `get` of the patch on offer leaves the lock where it is, too.
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["get", UUID], &["--json"]);
    let env: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(hosted_events(&env), [event.clone()], "{env}");
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock);
    let (_, other) = requests(&server).await;
    assert_eq!(other, vec![earlier_index_path(); 4], "one request a run");

    // A registry that does not answer shows nothing either way: the lock
    // stays, quietly, after the one request.
    let server = MockServer::start().await;
    mount_api_beside_earlier(&server, &ARM_ONLY[..]).await;
    let api = server.uri();
    let earlier = earlier_index(&api);
    let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
    let (code, env) = scan_json(proj.path(), &api, &["--patch-server-url", api.as_str()]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED)
    );
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(hosted_events(&env), [event], "{env}");
    let (_, other) = requests(&server).await;
    assert_eq!(other, [earlier_index_path()], "asked once");
}

/// The uncounted event of a build the run put back on upstream's gem: the
/// patched build its lock entry pinned was withdrawn.
fn withdrawn_event(platform: &str) -> Value {
    json!({
        "action": "skipped",
        "purl": format!("{PURL}?platform={platform}"),
        "errorCode": "gem_upstream_build_kept",
        "reason": format!(
            "the patch registry serves upstream's own gem for {platform}: its patched build was \
             withdrawn"
        ),
        "details": { "gemFix": UUID, "platform": platform, "withdrawn": true, "mode": "hosted" },
    })
}

/// The patched `x86_64-linux-gnu` build the lock pins from an earlier
/// patch was withdrawn: that patch's registry, under the snapshot the lock
/// names, no longer lists the build (or lists another sha256 for it), so
/// an install on that platform fails there. The patch on offer has no
/// patched build for that platform. Staying would keep the install
/// broken, so the lock moves: one request to the registry it is on, both
/// files rewritten for the patch on offer with upstream's sha256 back for
/// that build, exit 0, no warning, and the run says in one line and one
/// uncounted event that the build is back on upstream's gem. A dry run
/// previews the same and writes nothing; a further run changes nothing,
/// asks no registry, and no longer speaks of a withdrawal.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_build_on_an_earlier_patch_moves_the_lock_to_the_patch_on_offer() {
    let line = format!(
        "{DEP} {DEP_VERSION}: patched for {ARM}; upstream gem back for {LINUX} (its patched \
         build was withdrawn)"
    );
    let other_sha = "b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3";
    for served in [None, Some(other_sha)] {
        let server = MockServer::start().await;
        mount_api_beside_earlier(&server, &ARM_ONLY[..]).await;
        mount_earlier_listing(&server, served).await;
        let api = server.uri();
        let (earlier, offered) = (
            earlier_index(&api),
            format!("{}/", index_url(&api, Some(4))),
        );
        let known = ["--patch-server-url", api.as_str()];

        // A dry run first: the same outcome, nothing written.
        let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
        let before = read(proj.path(), "Gemfile.lock");
        let (code, env) = scan_json(proj.path(), &api, &[known[0], known[1], "--dry-run"]);
        assert_eq!(code, 0, "{served:?}: {env}");
        assert_eq!(read(proj.path(), "Gemfile.lock"), before, "{served:?}");
        assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&earlier));
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        assert_eq!(
            hosted_events(&env),
            [
                patched_event("verified", ARM, ARM_UUID, true),
                withdrawn_event(LINUX)
            ],
            "{served:?}: {env}"
        );
        let (code, stdout, stderr) = hosted(
            proj.path(),
            &api,
            &["scan"],
            &[known[0], known[1], "--dry-run"],
        );
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        assert!(
            stdout.contains(&format!(
                "\n{DEP} {DEP_VERSION}: would be patched for {ARM}; upstream gem would be back \
                 for {LINUX} (its patched build was withdrawn)\n"
            )),
            "{served:?}:\n{stdout}"
        );
        assert_eq!(read(proj.path(), "Gemfile.lock"), before, "{served:?}");

        // The run.
        let asked_before = requests(&server).await.1.len();
        let (code, env) = scan_json(proj.path(), &api, &known);
        assert_eq!(code, 0, "{served:?}: {env}");
        assert_eq!(env["status"], "success", "{env}");
        assert_eq!(
            read(proj.path(), "Gemfile.lock"),
            hosted_lock(&offered, ARM_PATCHED, LINUX_UPSTREAM),
            "{served:?}: on the patch on offer, upstream's sha256 back for linux"
        );
        assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&offered));
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        assert_eq!(
            hosted_events(&env),
            [
                patched_event("applied", ARM, ARM_UUID, true),
                withdrawn_event(LINUX)
            ],
            "{served:?}: {env}"
        );
        let summary = &env["summary"];
        assert_eq!(
            (&summary["applied"], &summary["skipped"], &summary["failed"]),
            (&json!(1), &json!(0), &json!(0)),
            "the build back on upstream's gem is counted nowhere: {env}"
        );
        assert_eq!(
            env["redirect"]["rewrittenFiles"],
            json!(["Gemfile", "Gemfile.lock"])
        );
        let (_, other) = requests(&server).await;
        assert_eq!(
            other[asked_before..],
            [earlier_index_path()],
            "{served:?}: one request, to the registry the lock was on"
        );

        // A further run: in place, nothing asked, no withdrawal to speak of.
        let (code, env) = scan_json(proj.path(), &api, &known);
        assert_eq!(code, 0, "{env}");
        assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{env}");
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        assert_eq!(
            hosted_events(&env),
            [
                patched_event("applied", ARM, ARM_UUID, false),
                upstream_event(LINUX)
            ],
            "{served:?}: {env}"
        );
        let (_, other) = requests(&server).await;
        assert_eq!(other.len(), asked_before + 1, "no registry request");

        // For a person: the one line on stdout, and nothing that warns.
        let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
        let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &known);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        assert!(
            stdout.contains("Switched 1 package to hosted patches; rewrote 2 files.\n"),
            "{stdout}"
        );
        assert!(stdout.contains(&format!("\n{line}\n")), "{stdout}");
        assert!(
            !stderr.contains("Warning")
                && !stderr.contains("Skipped")
                && !stderr.contains("Not hosted"),
            "{stderr}"
        );
        assert_eq!(
            read(proj.path(), "Gemfile.lock"),
            hosted_lock(&offered, ARM_PATCHED, LINUX_UPSTREAM)
        );

        // `get` of the patch on offer moves the lock the same way.
        let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
        let (code, stdout, stderr) = hosted(
            proj.path(),
            &api,
            &["get", UUID],
            &["--json", known[0], known[1]],
        );
        let env: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
        assert_eq!(code, 0, "{env}\n{stderr}");
        assert_eq!(
            hosted_events(&env),
            [
                patched_event("applied", ARM, ARM_UUID, true),
                withdrawn_event(LINUX)
            ],
            "{served:?}: {env}"
        );
        assert_eq!(
            read(proj.path(), "Gemfile.lock"),
            hosted_lock(&offered, ARM_PATCHED, LINUX_UPSTREAM)
        );
    }
}

/// On a terminal the line of a build that is back on upstream's gem breaks
/// after its first clause, under a hanging indent, at 80, 100 and 120
/// columns, and neither row is wider than the terminal. (In a pipe it is
/// one line: the cases above read it there.)
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_line_of_a_withdrawn_build_fits_a_terminal_of_80_100_and_120_columns() {
    let server = MockServer::start().await;
    mount_api_beside_earlier(&server, &ARM_ONLY[..]).await;
    mount_earlier_listing(&server, None).await;
    let api = server.uri();
    let earlier = earlier_index(&api);
    for cols in [80u16, 100, 120] {
        let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
        let cwd = proj.path().to_path_buf();
        let api = api.clone();
        let run = tokio::task::spawn_blocking(move || {
            let dir = cwd.to_str().expect("utf8 temp path");
            let args = [
                "scan",
                "--mode",
                "hosted",
                "--yes",
                "--cwd",
                dir,
                "--api-url",
                api.as_str(),
                "--org",
                ORG,
                "--api-token",
                API_TOKEN,
                "--patch-server-url",
                api.as_str(),
            ];
            pty_io::run_command_at(
                cols,
                common::hermetic::pty_binary_command(),
                &args,
                &cwd,
                &[],
                &[],
                std::time::Duration::from_secs(60),
            )
        })
        .await
        .expect("spawn_blocking join");
        let screen = pty_io::render(run.output.as_bytes());
        let shown = screen.join("\n");
        println!("--- {cols} columns\n{shown}");
        assert_eq!(run.code, 0, "{shown}");
        let at = screen
            .iter()
            .position(|row| row.starts_with(&format!("{DEP} {DEP_VERSION}: ")))
            .unwrap_or_else(|| panic!("no line of the gem:\n{shown}"));
        assert_eq!(
            screen[at..at + 2],
            [
                format!("{DEP} {DEP_VERSION}: patched for {ARM};"),
                format!("  upstream gem back for {LINUX} (its patched build was withdrawn)"),
            ],
            "{cols} columns:\n{shown}"
        );
        assert!(
            screen[at..at + 2]
                .iter()
                .all(|row| row.chars().count() <= usize::from(cols)),
            "wider than {cols} columns:\n{shown}"
        );
    }
}

/// The same withdrawal where the patch on offer has no patched build for
/// any platform the lock names. A lock on its upstream registry would be
/// left there (nothing to gain); a lock on a registry that refuses a build
/// it pins is not: it moves to the patch on offer all the same, every
/// build on upstream's sha256, so that every platform installs again. The
/// gem is then no package on a hosted patch. The run's own VEX and a
/// later `vex` say `affected` of both builds.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_build_moves_the_lock_to_a_patch_with_no_patched_build_at_all() {
    let server = MockServer::start().await;
    mount_api_beside_earlier(&server, &NONE_PATCHED[..]).await;
    mount_earlier_listing(&server, None).await;
    mount_index(&server, ARM_UPSTREAM, LINUX_UPSTREAM).await;
    let api = server.uri();
    let (earlier, offered) = (
        earlier_index(&api),
        format!("{}/", index_url(&api, Some(4))),
    );
    let known = ["--patch-server-url", api.as_str()];
    let line = format!(
        "{DEP} {DEP_VERSION}: upstream gem back for {LINUX} (its patched build was withdrawn); \
         upstream gem kept for {ARM} (no patched build yet)"
    );

    let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
    let (code, env, doc) = scan_vex(proj.path(), &api);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&offered, ARM_UPSTREAM, LINUX_UPSTREAM),
        "on the patch on offer, every build on upstream's sha256"
    );
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&offered));
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [upstream_event(ARM), withdrawn_event(LINUX)],
        "{env}"
    );
    let summary = &env["summary"];
    assert_eq!(
        (&summary["applied"], &summary["skipped"], &summary["failed"]),
        (&json!(0), &json!(0), &json!(0)),
        "{env}"
    );
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        json!(["Gemfile", "Gemfile.lock"])
    );
    let (_, other) = requests(&server).await;
    assert_eq!(other, [earlier_index_path()], "one registry request");
    // The run's own document: both builds affected. No build is
    // attested, so the gem without a platform stands for affected builds
    // alone and is named beside each.
    let affected = |platform: &str| {
        let mut statement = upstream_statement(platform);
        statement.products.insert(0, PURL.to_string());
        statement
    };
    assert_eq!(
        said(&doc.expect("a document")),
        [affected(ARM), affected(LINUX)],
        "{env}"
    );
    assert_eq!(env["vex"]["affected"], 2, "{env}");
    // And a later `vex` over the lock the run left.
    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(said(out.doc()), [affected(ARM), affected(LINUX)], "{out}");
    assert_eq!(out.envelope["status"], "success", "{out}");

    // For a person.
    let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &known);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("Switched 0 packages to hosted patches; rewrote 2 files.\n"),
        "{stdout}"
    );
    assert!(stdout.contains(&format!("\n{line}\n")), "{stdout}");
    assert!(
        !stderr.contains("Warning")
            && !stderr.contains("No patches could be switched")
            && !stderr.contains("Not hosted"),
        "{stderr}"
    );
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&offered, ARM_UPSTREAM, LINUX_UPSTREAM)
    );
}

/// The same lock with no `CHECKSUMS` says nothing of what it installs, so
/// the run asks the registry the lock is on, once: its compact-index
/// document for the gem. A registry that lists a patched build for
/// `x86_64-linux-gnu` keeps the lock where it is. One that lists
/// upstream's gem has nothing to lose, and the lock moves to the patch on
/// offer. A registry that does not answer keeps the lock where it is.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_without_checksums_on_an_earlier_patch_is_judged_by_its_registry() {
    let (line, event) = newer_fix_waits();

    // The registry lists a patched build: the lock stays.
    let server = MockServer::start().await;
    mount_api_beside_earlier(&server, &ARM_ONLY[..]).await;
    mount_earlier_index(&server, EARLIER_LINUX_PATCHED).await;
    let api = server.uri();
    let earlier = earlier_index(&api);
    let known = ["--patch-server-url", api.as_str()];
    let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, false);
    let lock = read(proj.path(), "Gemfile.lock");
    assert!(!lock.contains("CHECKSUMS"), "premise: {lock}");
    let (code, env) = scan_json(proj.path(), &api, &known);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock);
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&earlier));
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(hosted_events(&env), [event.clone()], "{env}");
    let (_, other) = requests(&server).await;
    assert_eq!(
        other,
        [earlier_index_path()],
        "one request, to the registry the lock is on"
    );
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &known);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains(&format!("\n{line}\n")), "{stdout}");
    assert!(!stderr.contains("Warning"), "{stderr}");

    // The registry lists upstream's gem: nothing to lose, the lock moves.
    let server = MockServer::start().await;
    mount_api_beside_earlier(&server, &ARM_ONLY[..]).await;
    mount_earlier_index(&server, LINUX_UPSTREAM).await;
    let api = server.uri();
    let (earlier, offered) = (
        earlier_index(&api),
        format!("{}/", index_url(&api, Some(4))),
    );
    let known = ["--patch-server-url", api.as_str()];
    let proj = hosted_project(&earlier, ARM_UPSTREAM, LINUX_UPSTREAM, false);
    let (code, env) = scan_json(proj.path(), &api, &known);
    assert_eq!(code, 0, "{env}");
    let after = read(proj.path(), "Gemfile.lock");
    assert!(
        after.starts_with(&format!(
            "GEM\n  remote: {offered}\n  specs:\n    {DEP} ({DEP_VERSION}-{ARM})\n    {DEP} \
             ({DEP_VERSION}-{LINUX})\n\nGEM\n  remote: https://rubygems.org/\n"
        )),
        "{after}"
    );
    assert!(!after.contains(EARLIER_UUID), "{after}");
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&offered));
    assert_eq!(
        warning_codes(&env),
        ["redirect_gem_no_checksums_section"],
        "the lock's own caveat alone: {env}"
    );
    assert_eq!(
        hosted_events(&env),
        [
            patched_event("applied", ARM, ARM_UUID, true),
            upstream_event(LINUX)
        ],
        "{env}"
    );
    let (_, other) = requests(&server).await;
    assert_eq!(other, [earlier_index_path()], "one registry request");

    // The registry does not answer: nothing shows what the lock installs.
    let server = MockServer::start().await;
    mount_api_beside_earlier(&server, &ARM_ONLY[..]).await;
    let api = server.uri();
    let earlier = earlier_index(&api);
    let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, false);
    let lock = read(proj.path(), "Gemfile.lock");
    let (code, env) = scan_json(proj.path(), &api, &["--patch-server-url", api.as_str()]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock);
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(hosted_events(&env), [event], "{env}");
    let (_, other) = requests(&server).await;
    assert_eq!(other, [earlier_index_path()], "asked once");
}

/// The patch on offer patches every build the earlier patch does: the
/// lock loses nothing, so it moves to the offered patch's registry, and
/// the run reports each locked build under the patch it then installs.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_on_an_earlier_patch_moves_to_a_patch_that_patches_as_much() {
    let server = MockServer::start().await;
    mount_api_beside_earlier(&server, &ONE_PATCHED[..]).await;
    let api = server.uri();
    let (earlier, offered) = (
        earlier_index(&api),
        format!("{}/", index_url(&api, Some(4))),
    );
    let known = ["--patch-server-url", api.as_str()];

    let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
    let (code, env) = scan_json(proj.path(), &api, &known);
    assert_eq!(code, 0, "{env}");
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&offered, ARM_UPSTREAM, LINUX_PATCHED)
    );
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&offered));
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        [
            upstream_event(ARM),
            patched_event("applied", LINUX, LINUX_UUID, true)
        ],
        "{env}"
    );
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        json!(["Gemfile", "Gemfile.lock"])
    );
    let (_, other) = requests(&server).await;
    assert_eq!(other, Vec::<String>::new(), "no registry request");

    let proj = hosted_project(&earlier, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, true);
    let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &known);
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

/// Under a patch mirror the lock names the earlier patch's registry on
/// the mirror, which may ask for credentials the run was never given. The
/// document is read where the patch server serves it, like every download
/// of the run, and the mirror is asked nothing about it.
#[tokio::test(flavor = "multi_thread")]
async fn the_registry_of_a_lock_on_a_patch_mirror_is_read_from_the_patch_server() {
    const PREFIX: &str = "/artifactory/socket-patch";
    let server = MockServer::start().await;
    mount_api_beside_earlier(&server, &ARM_ONLY[..]).await;
    mount_earlier_index(&server, EARLIER_LINUX_PATCHED).await;
    let api = server.uri();
    // The mirror takes the run's check of the pin it would write, and
    // wants credentials for anything else.
    let mirror = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(path(format!(
            "{PREFIX}/patch/gem/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.gem"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mirror)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mirror)
        .await;
    let base = format!("{}{PREFIX}", mirror.uri());

    let on_mirror = earlier_index(&base);
    let proj = hosted_project(&on_mirror, ARM_UPSTREAM, EARLIER_LINUX_PATCHED, false);
    let lock = read(proj.path(), "Gemfile.lock");
    let (code, env) = scan_json(proj.path(), &api, &["--patch-mirror-url", base.as_str()]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock);
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&on_mirror));
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(hosted_events(&env), [newer_fix_waits().1], "{env}");
    let (_, other) = requests(&server).await;
    assert_eq!(
        other,
        [earlier_index_path()],
        "the patch server is asked, once"
    );
    let asked_of_mirror: Vec<String> = mirror
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|request| format!("{} {}", request.method, request.url.path()))
        .filter(|request| request.contains("/info/"))
        .collect();
    assert_eq!(asked_of_mirror, Vec::<String>::new());
}

// ── A lock that stays on a patch which withdrew a build ───────────────

/// The patch of the earlier patch's patched `arm64-darwin` build, and the
/// sha256 of that build.
const EARLIER_ARM_UUID: &str = "4d5e6f7a-8b9c-4d0e-9f1a-2b3c4d5e6f7a";
const EARLIER_ARM_PATCHED: &str =
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
/// The earlier patch with a patched build for both platforms, as the lock
/// of these tests has it (snapshot `3`).
const EARLIER_BOTH: [Listed; 2] = [
    (ARM, EARLIER_ARM_PATCHED, Some(EARLIER_ARM_UUID)),
    (LINUX, EARLIER_LINUX_PATCHED, Some(EARLIER_LINUX_UUID)),
];
/// The snapshot the earlier patch's reference names once a build of it was
/// withdrawn.
const EARLIER_NOW: u32 = 6;

/// What the patch service answers when it is asked for the reference of
/// the earlier patch.
#[derive(Clone)]
enum EarlierNow {
    /// Granted, listing these builds at the snapshot [`EARLIER_NOW`].
    Lists(Vec<Listed>),
    /// Granted, with no list of the version's gems.
    NoList,
    /// Granted, as the reference of another package.
    OtherPackage,
    /// Not granted: this status.
    Status(&'static str),
    /// No answer for that patch.
    Absent,
    /// The request fails.
    Fails,
}

/// The patch API of the patch on offer ([`UUID`], whose reference lists
/// `offered` at snapshot `4`), which answers a reference request with the
/// patches it was asked for and no other: the one on offer, and the
/// earlier patch as `earlier` says. The earlier patch's record is served
/// too, for a VEX document.
async fn mount_api_refreshing(server: &MockServer, offered: &[Listed], earlier: EarlierNow) {
    let api = server.uri();
    let on_offer = reference(&api, UUID, Some((offered, 4)));
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(move |request: &wiremock::Request| {
            let asked: Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let asked: Vec<&str> = asked["uuids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let mut results = serde_json::Map::new();
            if asked.contains(&UUID) {
                results.insert(UUID.to_string(), on_offer.clone());
            }
            if asked.contains(&EARLIER_UUID) {
                let answer = match &earlier {
                    EarlierNow::Lists(builds) => Some(reference(
                        &api,
                        EARLIER_UUID,
                        Some((&builds[..], EARLIER_NOW)),
                    )),
                    EarlierNow::NoList => Some(reference(&api, EARLIER_UUID, None)),
                    EarlierNow::OtherPackage => {
                        let mut other =
                            reference(&api, EARLIER_UUID, Some((&EARLIER_BOTH[..], EARLIER_NOW)));
                        other["purl"] = json!("pkg:gem/another-gem@1.19.3");
                        Some(other)
                    }
                    EarlierNow::Status(status) => Some(json!({ "status": status })),
                    EarlierNow::Absent => None,
                    EarlierNow::Fails => return ResponseTemplate::new(500),
                };
                results.extend(answer.map(|answer| (EARLIER_UUID.to_string(), answer)));
            }
            ResponseTemplate::new(200).set_body_json(json!({ "results": results }))
        })
        .with_priority(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{EARLIER_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": EARLIER_UUID, "purl": PURL, "publishedAt": "2025-12-01T00:00:00Z",
            "files": { "lib/platform_probe.rb": {
                "beforeHash": "a".repeat(64), "afterHash": "c".repeat(64),
            }},
            "vulnerabilities": { GHSA: {
                "cves": ["CVE-2026-5555"], "summary": "s", "severity": "high",
                "description": "d",
            }},
            "description": "x", "license": "MIT", "tier": "free",
        })))
        .mount(server)
        .await;
    mount_api(server, Some((offered, 4))).await;
}

/// The compact-index document of the earlier patch's registry at
/// `snapshot`: the patched ruby gem and `builds` (`(platform, sha256)`).
async fn mount_earlier_snapshot(server: &MockServer, snapshot: u32, builds: &[(&str, &str)]) {
    let mut listing = format!("---\n{DEP_VERSION} racc:~> 1.4|checksum:{RUBY_PATCHED}\n");
    for (platform, sha256) in builds {
        listing.push_str(&format!(
            "{DEP_VERSION}-{platform} racc:~> 1.4|checksum:{sha256}\n"
        ));
    }
    Mock::given(method("GET"))
        .and(path(earlier_snapshot_path(snapshot)))
        .respond_with(ResponseTemplate::new(200).set_body_string(listing))
        .mount(server)
        .await;
}

fn earlier_snapshot_path(snapshot: u32) -> String {
    format!("/patch-registry/gem/{TOKEN}/{EARLIER_UUID}/s/{snapshot}/info/{DEP}")
}

/// An event of a build of the gem under the earlier patch: `applied`
/// (`verified` on a dry run) under `patch`, or, with none, the uncounted
/// event of a build that is back on upstream's gem.
fn earlier_event(action: &str, platform: &str, patch: Option<&str>) -> Value {
    let purl = format!("{PURL}?platform={platform}");
    match patch {
        Some(patch) => json!({
            "action": action, "purl": purl, "uuid": patch,
            "details": { "gemFix": EARLIER_UUID, "platform": platform, "mode": "hosted" },
        }),
        None => json!({
            "action": "skipped", "purl": purl, "errorCode": "gem_upstream_build_kept",
            "reason": format!(
                "the patch registry serves upstream's own gem for {platform}: its patched \
                 build was withdrawn"
            ),
            "details": {
                "gemFix": EARLIER_UUID, "platform": platform, "withdrawn": true,
                "mode": "hosted",
            },
        }),
    }
}

/// The counted skip of the patch on offer: its code and its line.
fn offer_skip(code: &str, line: &str) -> Value {
    json!({
        "action": "skipped", "purl": PURL, "uuid": UUID,
        "errorCode": code, "reason": line,
        "details": { "mode": "hosted" },
    })
}

/// One situation in which a lock stays on the earlier patch: what the
/// patch on offer lists, the build the earlier patch withdrew and the one
/// it still serves (each with the sha256 the lock pins and the patch of
/// that build), the sha256 of upstream's gem for the withdrawn one, and
/// the quiet skip of the patch on offer.
struct Stays {
    offered: Vec<Listed>,
    withdrawn: (&'static str, &'static str),
    served: (&'static str, &'static str, &'static str),
    upstream: &'static str,
    skip: (&'static str, String),
}

impl Stays {
    /// The patch on offer serves upstream's gem for both platforms: the
    /// lock is held for the linux build, and arm64-darwin was withdrawn.
    fn held() -> Stays {
        Stays {
            offered: NONE_PATCHED.to_vec(),
            withdrawn: (ARM, EARLIER_ARM_PATCHED),
            served: (LINUX, EARLIER_LINUX_PATCHED, EARLIER_LINUX_UUID),
            upstream: ARM_UPSTREAM,
            skip: ("redirect_gem_newer_fix_waits", newer_fix_waits().0),
        }
    }

    /// The patch on offer does not list arm64-darwin, and has a patched
    /// build for linux, which the earlier patch withdrew.
    fn unlisted() -> Stays {
        Stays {
            offered: vec![(LINUX, LINUX_PATCHED, Some(LINUX_UUID))],
            withdrawn: (LINUX, EARLIER_LINUX_PATCHED),
            served: (ARM, EARLIER_ARM_PATCHED, EARLIER_ARM_UUID),
            upstream: LINUX_UPSTREAM,
            skip: (
                "redirect_gem_platform_unlisted",
                format!(
                    "{DEP} {DEP_VERSION}: the newer fix's registry does not list {ARM}; the lock \
                     stays on the patch it is on"
                ),
            ),
        }
    }

    /// What the earlier patch's reference lists once the build was
    /// withdrawn: upstream's gem for it, the other build as it was.
    fn earlier_now(&self) -> Vec<Listed> {
        let mut now = vec![
            (self.withdrawn.0, self.upstream, None),
            (self.served.0, self.served.1, Some(self.served.2)),
        ];
        now.sort();
        now
    }

    /// `(arm64-darwin, x86_64-linux-gnu)` as the lock pins them once it
    /// followed the earlier patch's reference.
    fn pins_now(&self) -> (&'static str, &'static str) {
        if self.withdrawn.0 == ARM {
            (self.upstream, self.served.1)
        } else {
            (self.served.1, self.upstream)
        }
    }

    /// The stand-in for this situation: the earlier patch's registry at
    /// the snapshot the lock names lists the build it still serves and
    /// not the withdrawn one, and at its current snapshot what its
    /// reference lists.
    async fn mount(&self, server: &MockServer, earlier: EarlierNow) {
        mount_api_refreshing(server, &self.offered, earlier).await;
        mount_earlier_snapshot(server, 3, &[(self.served.0, self.served.1)]).await;
        let now: Vec<(&str, &str)> = self
            .earlier_now()
            .iter()
            .map(|(platform, sha256, _)| (*platform, *sha256))
            .collect();
        mount_earlier_snapshot(server, EARLIER_NOW, &now).await;
    }

    /// The line of the earlier patch's builds once the lock followed its
    /// reference.
    fn line(&self, dry_run: bool) -> String {
        let back = if dry_run { "would be back" } else { "back" };
        format!(
            "{DEP} {DEP_VERSION}: patched for {}; upstream gem {back} for {} (its patched build \
             was withdrawn)",
            self.served.0, self.withdrawn.0
        )
    }

    /// The run's hosted events once the lock followed the earlier patch's
    /// reference, in envelope order.
    fn events(&self, action: &str) -> Vec<Value> {
        let mut builds = vec![
            earlier_event(action, self.withdrawn.0, None),
            earlier_event(action, self.served.0, Some(self.served.2)),
        ];
        builds.sort_by_key(|event| event["purl"].as_str().map(str::to_string));
        let mut events = vec![offer_skip(self.skip.0, &self.skip.1)];
        events.extend(builds);
        events
    }
}

/// A project whose lock is on the earlier patch at snapshot `3`, with both
/// builds patched there.
fn project_on_earlier(api: &str, checksums: bool) -> tempfile::TempDir {
    let earlier = earlier_index(api);
    hosted_project(
        &earlier,
        EARLIER_ARM_PATCHED,
        EARLIER_LINUX_PATCHED,
        checksums,
    )
}

/// A lock stays on an earlier patch of the gem (the patch on offer would
/// take a patched build from it, or does not list a locked platform), and
/// that patch has withdrawn another build the lock pins: its registry,
/// asked once, no longer lists it, so that platform no longer installs.
/// The run brings the lock to the earlier patch's current listing: both
/// files name its current snapshot, the withdrawn build is back on
/// upstream's sha256 and the build it still serves is as it was. Exit 0
/// with no warning: the earlier patch's builds are reported as for a lock
/// that follows a withdrawal on its own patch, the patch on offer is
/// skipped under its quiet code, and a person reads the two lines. A
/// `scan` holds the earlier patch's reference already (it asks about
/// every pin before it rewrites), so it asks for nothing more; a dry run
/// previews the same and writes nothing; a second run changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_that_stays_is_brought_to_the_current_listing_of_the_patch_it_is_on() {
    for case in [Stays::held(), Stays::unlisted()] {
        let code = case.skip.0;
        let server = MockServer::start().await;
        case.mount(&server, EarlierNow::Lists(case.earlier_now()))
            .await;
        let api = server.uri();
        let (before, now) = (
            earlier_index(&api),
            format!("{}/", registry_url(&api, EARLIER_UUID, Some(EARLIER_NOW))),
        );
        let (arm, linux) = case.pins_now();
        let known = ["--patch-server-url", api.as_str()];
        let pair_before = (
            hosted_lock(&before, EARLIER_ARM_PATCHED, EARLIER_LINUX_PATCHED),
            hosted_gemfile(&before),
        );
        let pair_now = (hosted_lock(&now, arm, linux), hosted_gemfile(&now));
        let pair = |proj: &Path| (read(proj, "Gemfile.lock"), read(proj, "Gemfile"));

        // A dry run: the same outcome, nothing written.
        let proj = project_on_earlier(&api, true);
        let (exit, env) = scan_json(proj.path(), &api, &[known[0], known[1], "--dry-run"]);
        assert_eq!(exit, 0, "{code}: {env}");
        assert_eq!(pair(proj.path()), pair_before, "{code}");
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        assert_eq!(
            hosted_events(&env),
            case.events("verified"),
            "{code}: {env}"
        );
        let (exit, stdout, stderr) = hosted(
            proj.path(),
            &api,
            &["scan"],
            &[known[0], known[1], "--dry-run"],
        );
        assert_eq!(exit, 0, "{stdout}\n{stderr}");
        for line in [case.line(true), case.skip.1.clone()] {
            assert!(stdout.contains(&format!("\n{line}\n")), "{line}\n{stdout}");
        }
        assert_eq!(pair(proj.path()), pair_before, "{code}");

        // The run.
        let asked_before = requests(&server).await;
        let (exit, env) = scan_json(proj.path(), &api, &known);
        assert_eq!(exit, 0, "{code}: {env}");
        assert_eq!(env["status"], "success", "{env}");
        assert_eq!(pair(proj.path()), pair_now, "{code}");
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        assert_eq!(hosted_events(&env), case.events("applied"), "{code}: {env}");
        let summary = &env["summary"];
        assert_eq!(
            (&summary["applied"], &summary["skipped"], &summary["failed"]),
            (&json!(1), &json!(1), &json!(0)),
            "{code}: {env}"
        );
        assert_eq!(
            env["redirect"]["rewrittenFiles"],
            json!(["Gemfile", "Gemfile.lock"])
        );
        let (references, other) = requests(&server).await;
        assert_eq!(
            other[asked_before.1.len()..],
            [earlier_snapshot_path(3)],
            "{code}: one request to the registry the lock is on"
        );
        assert_eq!(
            references[asked_before.0.len()..],
            [vec![EARLIER_UUID.to_string()], vec![UUID.to_string()]],
            "{code}: the scan's check of the pin, and the patch on offer: no further request"
        );

        // A second run: the registry lists what the lock pins, so the
        // lock is as it is, and the earlier patch's builds are no news.
        let asked_before = requests(&server).await;
        let (exit, env) = scan_json(proj.path(), &api, &known);
        assert_eq!(exit, 0, "{code}: {env}");
        assert_eq!(pair(proj.path()), pair_now, "{code}");
        assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{env}");
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        assert_eq!(
            hosted_events(&env),
            [offer_skip(case.skip.0, &case.skip.1)],
            "{code}: {env}"
        );
        let (references, other) = requests(&server).await;
        assert_eq!(
            other[asked_before.1.len()..],
            [earlier_snapshot_path(EARLIER_NOW)],
            "{code}"
        );
        assert_eq!(
            references[asked_before.0.len()..],
            [vec![EARLIER_UUID.to_string()], vec![UUID.to_string()]],
            "{code}"
        );

        // For a person: the two lines on stdout, and nothing that warns.
        let proj = project_on_earlier(&api, true);
        let (exit, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &known);
        assert_eq!(exit, 0, "{stdout}\n{stderr}");
        for line in [case.line(false), case.skip.1.clone()] {
            assert!(stdout.contains(&format!("\n{line}\n")), "{line}\n{stdout}");
        }
        assert!(
            !stderr.contains("Warning")
                && !stderr.contains("No patches could be switched")
                && !stderr.contains("Not hosted"),
            "{code}: {stderr}"
        );
        assert_eq!(pair(proj.path()), pair_now, "{code}");
    }
}

/// `get` of the patch on offer, and a `scan` that does not know the
/// lock's patch server as one, hold no answer for the earlier patch: they
/// ask for its reference, once, after the registry showed the withdrawal,
/// and bring the lock to it as above. Without a withdrawal nothing is
/// asked of the patch service beyond the patch on offer.
#[tokio::test(flavor = "multi_thread")]
async fn a_run_that_holds_no_answer_asks_for_the_reference_of_the_patch_the_lock_stays_on() {
    for case in [Stays::held(), Stays::unlisted()] {
        let code = case.skip.0;
        let server = MockServer::start().await;
        case.mount(&server, EarlierNow::Lists(case.earlier_now()))
            .await;
        let api = server.uri();
        let now = format!("{}/", registry_url(&api, EARLIER_UUID, Some(EARLIER_NOW)));
        let (arm, linux) = case.pins_now();
        let known = ["--patch-server-url", api.as_str()];
        let asks = [vec![UUID.to_string()], vec![EARLIER_UUID.to_string()]];

        // `get`.
        let proj = project_on_earlier(&api, true);
        let (exit, stdout, stderr) = hosted(
            proj.path(),
            &api,
            &["get", UUID],
            &["--json", known[0], known[1]],
        );
        let env: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
        assert_eq!(exit, 0, "{code}: {env}\n{stderr}");
        assert_eq!(
            read(proj.path(), "Gemfile.lock"),
            hosted_lock(&now, arm, linux)
        );
        assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&now));
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        assert_eq!(hosted_events(&env), case.events("applied"), "{code}: {env}");
        let (references, other) = requests(&server).await;
        assert_eq!(
            references, asks,
            "{code}: one request for the earlier patch"
        );
        assert_eq!(other, [earlier_snapshot_path(3)], "{code}");
        // A second `get` asks for the patch on offer alone.
        let (exit, _, stderr) = hosted(
            proj.path(),
            &api,
            &["get", UUID],
            &["--json", known[0], known[1]],
        );
        assert_eq!(exit, 0, "{stderr}");
        assert_eq!(
            read(proj.path(), "Gemfile.lock"),
            hosted_lock(&now, arm, linux)
        );
        let (references, _) = requests(&server).await;
        assert_eq!(references[asks.len()..], [vec![UUID.to_string()]], "{code}");

        // A `scan` that was not told of the patch server (it takes the
        // origin from the reference of the patch on offer).
        let server = MockServer::start().await;
        case.mount(&server, EarlierNow::Lists(case.earlier_now()))
            .await;
        let api = server.uri();
        let now = format!("{}/", registry_url(&api, EARLIER_UUID, Some(EARLIER_NOW)));
        let proj = project_on_earlier(&api, true);
        let (exit, env) = scan_json(proj.path(), &api, &[]);
        assert_eq!(exit, 0, "{code}: {env}");
        assert_eq!(
            read(proj.path(), "Gemfile.lock"),
            hosted_lock(&now, arm, linux)
        );
        assert_eq!(hosted_events(&env), case.events("applied"), "{code}: {env}");
        let (references, other) = requests(&server).await;
        assert_eq!(references, asks, "{code}");
        assert_eq!(other, [earlier_snapshot_path(3)], "{code}");

        // No withdrawal: the registry lists both builds as the lock pins
        // them. The lock stays byte for byte, and nothing is asked about
        // the earlier patch.
        let server = MockServer::start().await;
        mount_api_refreshing(
            &server,
            &case.offered,
            EarlierNow::Lists(EARLIER_BOTH.to_vec()),
        )
        .await;
        mount_earlier_snapshot(
            &server,
            3,
            &[(ARM, EARLIER_ARM_PATCHED), (LINUX, EARLIER_LINUX_PATCHED)],
        )
        .await;
        let api = server.uri();
        let before = earlier_index(&api);
        let proj = project_on_earlier(&api, true);
        let (exit, stdout, stderr) = hosted(
            proj.path(),
            &api,
            &["get", UUID],
            &["--json", "--patch-server-url", api.as_str()],
        );
        let env: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
        assert_eq!(exit, 0, "{code}: {env}\n{stderr}");
        assert_eq!(
            read(proj.path(), "Gemfile.lock"),
            hosted_lock(&before, EARLIER_ARM_PATCHED, EARLIER_LINUX_PATCHED)
        );
        let skip = match code {
            "redirect_gem_newer_fix_waits" => format!(
                "{DEP} {DEP_VERSION}: the newer fix has no patched build for {ARM}, {LINUX} yet; \
                 the lock stays on the patch it is on"
            ),
            _ => case.skip.1.clone(),
        };
        assert_eq!(
            hosted_events(&env),
            [offer_skip(code, &skip)],
            "{code}: {env}"
        );
        let (references, other) = requests(&server).await;
        assert_eq!(references, [vec![UUID.to_string()]], "{code}");
        assert_eq!(
            other,
            [earlier_snapshot_path(3)],
            "{code}: the one document"
        );
    }
}

/// The reference of the patch the lock stays on is followed only when it
/// is usable. A patch that is not granted or still being built, an answer
/// that is missing, lists no builds, leaves a locked platform out or is
/// of another package, and a request that fails: the lock stays byte for
/// byte, the patch on offer is skipped quietly as before, and the run
/// says nothing more (no warning, no further event, exit 0).
#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_reference_leaves_the_lock_that_stays_as_it_is() {
    let case = Stays::held();
    let unusable = [
        (EarlierNow::Status("forbidden"), "not granted"),
        (EarlierNow::Status("pending_build"), "still being built"),
        (EarlierNow::Status("withdrawn"), "withdrawn"),
        (EarlierNow::Absent, "no answer"),
        (EarlierNow::NoList, "no list"),
        (
            EarlierNow::Lists(vec![(
                LINUX,
                EARLIER_LINUX_PATCHED,
                Some(EARLIER_LINUX_UUID),
            )]),
            "a list that leaves a locked platform out",
        ),
        (EarlierNow::OtherPackage, "another package"),
        (EarlierNow::Fails, "a request that fails"),
    ];
    for (earlier, why) in unusable {
        let server = MockServer::start().await;
        case.mount(&server, earlier).await;
        let api = server.uri();
        let before = earlier_index(&api);
        let proj = project_on_earlier(&api, true);
        let (exit, stdout, stderr) = hosted(
            proj.path(),
            &api,
            &["get", UUID],
            &["--json", "--patch-server-url", api.as_str()],
        );
        let env: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
        assert_eq!(exit, 0, "{why}: {env}\n{stderr}");
        assert_eq!(env["status"], "success", "{why}: {env}");
        assert_eq!(
            read(proj.path(), "Gemfile.lock"),
            hosted_lock(&before, EARLIER_ARM_PATCHED, EARLIER_LINUX_PATCHED),
            "{why}"
        );
        assert_eq!(
            read(proj.path(), "Gemfile"),
            hosted_gemfile(&before),
            "{why}"
        );
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{why}: {env}");
        assert_eq!(
            hosted_events(&env),
            [offer_skip(case.skip.0, &case.skip.1)],
            "{why}: {env}"
        );
        assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{why}");
        let (references, other) = requests(&server).await;
        assert_eq!(
            references,
            [vec![UUID.to_string()], vec![EARLIER_UUID.to_string()]],
            "{why}: asked once"
        );
        assert_eq!(other, [earlier_snapshot_path(3)], "{why}");
    }
}

/// A `scan` checks every pin before it rewrites. Where the earlier patch
/// as a whole was withdrawn, that check restores the gem to its upstream
/// registry first (each build back on the sha256 that registry lists),
/// and the patch on offer is then judged against a lock that is on no
/// patch: here it has no patched build for a locked platform, so the gem
/// is left on its upstream registry. Nothing is asked about the withdrawn
/// patch beyond that check.
#[tokio::test(flavor = "multi_thread")]
async fn a_scan_restores_a_wholly_withdrawn_earlier_patch_before_the_patch_on_offer_is_judged() {
    let case = Stays::held();
    let server = MockServer::start().await;
    case.mount(&server, EarlierNow::Status("withdrawn")).await;
    // The upstream registry, as the restore reads it.
    Mock::given(method("GET"))
        .and(path(format!("/upstream/info/{DEP}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "---\n{DEP_VERSION}-{ARM} racc:~> 1.4|checksum:{ARM_UPSTREAM}\n{DEP_VERSION}-{LINUX} \
             racc:~> 1.4|checksum:{LINUX_UPSTREAM}\n"
        )))
        .mount(&server)
        .await;
    let api = server.uri();
    let upstream = format!("{api}/upstream");
    let proj = project_on_earlier(&api, true);
    let args = [
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--json",
        "--cwd",
        proj.path().to_str().expect("utf8 temp path"),
        "--api-url",
        api.as_str(),
        "--org",
        ORG,
        "--api-token",
        API_TOKEN,
        "--patch-server-url",
        api.as_str(),
    ];
    let env = [("SOCKET_RUBYGEMS_URL", upstream.as_str())];
    let (exit, stdout, stderr) = common::run_with_env(proj.path(), &args, &env);
    let env: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}):\n{stdout}\nstderr:\n{stderr}"));
    assert_eq!(exit, 0, "{env}\n{stderr}");
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        (
            read(proj.path(), "Gemfile.lock"),
            read(proj.path(), "Gemfile")
        ),
        (lock(true), GEMFILE.to_string()),
        "the pair is back on its upstream registry: {env}"
    );
    let events: Vec<(String, String, String)> = env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|event| {
            let text = |key: &str| event[key].as_str().unwrap_or_default().to_string();
            (text("action"), text("uuid"), text("errorCode"))
        })
        .collect();
    assert_eq!(
        events,
        [
            (
                "rolledBack".to_string(),
                EARLIER_UUID.to_string(),
                "patch_withdrawn".to_string()
            ),
            (
                "skipped".to_string(),
                UUID.to_string(),
                "redirect_gem_no_patched_build".to_string()
            ),
        ],
        "{env}"
    );
    let (references, other) = requests(&server).await;
    assert_eq!(
        references,
        [vec![EARLIER_UUID.to_string()], vec![UUID.to_string()]],
        "the check of the pin and the patch on offer"
    );
    assert_eq!(
        other,
        [format!("/upstream/info/{DEP}")],
        "the upstream registry, and no patch registry"
    );
}

/// The run's own VEX and a later `vex` over the lock a refresh left agree
/// with it: the build the earlier patch still serves is attested under
/// its own patch, and the withdrawn one is stated as affected.
#[tokio::test(flavor = "multi_thread")]
async fn the_vex_of_a_lock_brought_to_its_patchs_current_listing_tells_the_builds_apart() {
    let case = Stays::held();
    let server = MockServer::start().await;
    case.mount(&server, EarlierNow::Lists(case.earlier_now()))
        .await;
    let api = server.uri();
    let now = format!("{}/", registry_url(&api, EARLIER_UUID, Some(EARLIER_NOW)));
    let (arm, linux) = case.pins_now();
    let statements = || {
        let mut affected = upstream_statement(ARM);
        affected.words = affected.words.replace(UUID, EARLIER_UUID);
        [
            patched_statement(&[(LINUX, EARLIER_LINUX_UUID)], false),
            affected,
        ]
    };
    let proj = project_on_earlier(&api, true);
    let (exit, env, doc) = scan_vex(proj.path(), &api);
    assert_eq!(exit, 0, "{env}");
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(
        read(proj.path(), "Gemfile.lock"),
        hosted_lock(&now, arm, linux)
    );
    assert_eq!(said(&doc.expect("a document")), statements(), "{env}");
    assert_eq!(
        (&env["vex"]["statements"], &env["vex"]["affected"]),
        (&json!(2), &json!(1)),
        "{env}"
    );
    let out = vex(proj.path(), &api);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(said(out.doc()), statements(), "{out}");
    assert_eq!(out.envelope["status"], "success", "{out}");
}

/// On a terminal the two lines of such a run stand one under the other at
/// 80, 100 and 120 columns, each broken after a clause where it does not
/// fit.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_lines_of_a_lock_that_stays_and_is_refreshed_fit_a_terminal() {
    for case in [Stays::held(), Stays::unlisted()] {
        let server = MockServer::start().await;
        case.mount(&server, EarlierNow::Lists(case.earlier_now()))
            .await;
        let api = server.uri();
        for cols in [80u16, 100, 120] {
            let proj = project_on_earlier(&api, true);
            let cwd = proj.path().to_path_buf();
            let api = api.clone();
            let run = tokio::task::spawn_blocking(move || {
                let dir = cwd.to_str().expect("utf8 temp path");
                let args = [
                    "scan",
                    "--mode",
                    "hosted",
                    "--yes",
                    "--cwd",
                    dir,
                    "--api-url",
                    api.as_str(),
                    "--org",
                    ORG,
                    "--api-token",
                    API_TOKEN,
                    "--patch-server-url",
                    api.as_str(),
                ];
                pty_io::run_command_at(
                    cols,
                    common::hermetic::pty_binary_command(),
                    &args,
                    &cwd,
                    &[],
                    &[],
                    std::time::Duration::from_secs(60),
                )
            })
            .await
            .expect("spawn_blocking join");
            let screen = pty_io::render(run.output.as_bytes());
            let shown = screen.join("\n");
            println!("--- {} at {cols} columns\n{shown}", case.skip.0);
            assert_eq!(run.code, 0, "{shown}");
            let at = screen
                .iter()
                .position(|row| row.starts_with(&format!("{DEP} {DEP_VERSION}: patched for ")))
                .unwrap_or_else(|| panic!("no line of the gem:\n{shown}"));
            // The rows of the two lines: each row after a line's first
            // hangs under two spaces, up to the next line of the output.
            let rows: Vec<&String> = screen[at..]
                .iter()
                .take_while(|row| row.starts_with(DEP) || row.starts_with("  "))
                .take_while(|row| !row.starts_with("  1. "))
                .collect();
            let mut lines: Vec<String> = Vec::new();
            for row in &rows {
                match (row.strip_prefix("  "), lines.last_mut()) {
                    (Some(rest), Some(line)) => {
                        line.push(' ');
                        line.push_str(rest);
                    }
                    _ => lines.push(row.to_string()),
                }
            }
            assert_eq!(
                lines,
                [case.line(false), case.skip.1.clone()],
                "{cols} columns:\n{shown}"
            );
            assert!(
                rows.iter()
                    .all(|row| row.chars().count() <= usize::from(cols)),
                "wider than {cols} columns:\n{shown}"
            );
            // A line that does not fit breaks after a clause where one
            // fits the terminal.
            let first_clause = |line: &str| line.split_once("; ").map(|(first, _)| first.len() + 1);
            for line in [case.line(false), case.skip.1.clone()] {
                let whole = line.chars().count() <= usize::from(cols);
                let clause = first_clause(&line).filter(|len| *len <= usize::from(cols));
                if let (false, Some(len)) = (whole, clause) {
                    assert!(
                        rows.iter().any(|row| **row == line[..len]),
                        "{cols} columns: {line}\n{shown}"
                    );
                }
            }
        }
    }
}

// ── A lock with no `CHECKSUMS` that follows a newer snapshot ──────────

/// A lock with no `CHECKSUMS` section is on the patch's registry at one
/// snapshot, and the reference names a newer one in which a platform that
/// was on upstream's gem has a patched build. The lock does not say what
/// that build was, so the run asks the snapshot the lock names, once, and
/// reports the build as newly patched: `newlyPatched` on its event, and
/// `now also patched for …` in the line. When that request fails the run
/// reports the builds as it does without it (none is new), and succeeds.
/// A lock with `CHECKSUMS` says what it had, and nothing is asked.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_without_checksums_on_a_newer_snapshot_says_which_build_is_now_patched() {
    let now_also =
        format!("{DEP} {DEP_VERSION}: now also patched for {ARM}; already patched for {LINUX}");
    let as_before = format!("{DEP} {DEP_VERSION}: patched for {ARM}, {LINUX}");
    // `(the lock has CHECKSUMS, the snapshot it names answers, arm64-darwin
    // is reported as new, the line, the registry requests)`.
    let cases = [
        (false, true, true, &now_also, 1),
        (false, false, false, &as_before, 1),
        (true, true, true, &now_also, 0),
    ];
    for (checksums, answers, newly, line, asked) in cases {
        let server = MockServer::start().await;
        mount_api(&server, Some((&BOTH_PATCHED[..], 5))).await;
        if answers {
            mount_index(&server, ARM_UPSTREAM, LINUX_PATCHED).await;
        }
        let api = server.uri();
        let (before, after) = (
            format!("{}/", index_url(&api, Some(4))),
            format!("{}/", index_url(&api, Some(5))),
        );
        let caveat: &[&str] = if checksums {
            &[]
        } else {
            &["redirect_gem_no_checksums_section"]
        };
        let what = format!("checksums {checksums}, answers {answers}");

        let proj = hosted_project(&before, ARM_UPSTREAM, LINUX_PATCHED, checksums);
        let (code, env) = scan_json(proj.path(), &api, &[]);
        assert_eq!(code, 0, "{what}: {env}");
        assert_eq!(env["status"], "success", "{what}: {env}");
        let lock = read(proj.path(), "Gemfile.lock");
        assert!(
            lock.contains(&format!("  remote: {after}\n")) && !lock.contains(&before),
            "{what}: {lock}"
        );
        assert_eq!(lock.contains("CHECKSUMS"), checksums, "{what}");
        assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&after));
        assert_eq!(warning_codes(&env), caveat, "{what}: {env}");
        assert_eq!(
            hosted_events(&env),
            [
                patched_event("applied", ARM, ARM_UUID, newly),
                patched_event("applied", LINUX, LINUX_UUID, false)
            ],
            "{what}: {env}"
        );
        let (_, other) = requests(&server).await;
        assert_eq!(other, vec![index_path(); asked], "{what}");

        // A second run: the lock names the reference's snapshot, so
        // nothing is asked and nothing is new.
        let (code, env) = scan_json(proj.path(), &api, &[]);
        assert_eq!(code, 0, "{what}: {env}");
        assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{what}");
        assert_eq!(
            hosted_events(&env),
            [
                patched_event("applied", ARM, ARM_UUID, false),
                patched_event("applied", LINUX, LINUX_UUID, false)
            ],
            "{what}: {env}"
        );
        let (_, other) = requests(&server).await;
        assert_eq!(other.len(), asked, "{what}: no registry request");

        // For a person, and a dry run.
        for dry_run in [true, false] {
            let proj = hosted_project(&before, ARM_UPSTREAM, LINUX_PATCHED, checksums);
            let extra: &[&str] = if dry_run { &["--dry-run"] } else { &[] };
            let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], extra);
            assert_eq!(code, 0, "{what}: {stdout}\n{stderr}");
            let line = match (dry_run, newly) {
                (true, true) => line.replace("now also patched", "would also be patched"),
                _ => line.to_string(),
            };
            assert!(
                stdout.contains(&format!("\n{line}\n")),
                "{what}, dry run {dry_run}:\n{stdout}"
            );
        }
    }
}

// ── A gem locked as its ruby-platform gem alone ───────────────────────

/// The sha256 a lock pins for upstream's ruby-platform gem.
const RUBY_UPSTREAM: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

/// A lock that names the gem as its ruby-platform gem alone, with
/// `platforms` as its `PLATFORMS` section.
fn ruby_lock(platforms: &[&str]) -> String {
    let platforms: String = platforms.iter().map(|p| format!("  {p}\n")).collect();
    format!(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    {DEP} ({DEP_VERSION})\n    racc \
         (1.8.1)\n\nPLATFORMS\n{platforms}\nDEPENDENCIES\n  {DEP} (= {DEP_VERSION})\n  racc (= \
         1.8.1)\n\nCHECKSUMS\n  {DEP} ({DEP_VERSION}) sha256={RUBY_UPSTREAM}\n  racc (1.8.1) \
         sha256={RACC}\n\nBUNDLED WITH\n  4.0.15\n"
    )
}

/// A project that locks the gem as its ruby-platform gem alone was pinned
/// by a reference with no list, whose registry URL has no snapshot level
/// (what release 5.1.0 writes). A scan whose reference names the registry
/// at a snapshot, with the list of the version's gems, leaves that pair
/// byte for byte and confirms the pin: the gem takes the registry without
/// the snapshot level, which lists the patched gems only. A lock that is
/// not pinned yet gets the same pair, whatever its `PLATFORMS` names.
#[tokio::test(flavor = "multi_thread")]
async fn a_gem_locked_as_its_ruby_gem_alone_stays_on_the_registry_without_a_snapshot() {
    let listed: [Listed; 3] = [
        (ARM, ARM_PATCHED, Some(ARM_UUID)),
        ("ruby", RUBY_PATCHED, Some(UUID)),
        (LINUX, LINUX_UPSTREAM, None),
    ];
    let pinned_event = json!({
        "action": "applied", "purl": PURL, "uuid": UUID, "details": { "mode": "hosted" },
    });
    for platforms in [&["ruby"][..], &[ARM, "ruby"][..]] {
        let server = MockServer::start().await;
        mount_api(&server, None).await;
        let api = server.uri();
        let root = index_url(&api, None);

        // The pair as a reference with no snapshot pins it.
        let proj = project(&ruby_lock(platforms));
        let (code, env) = scan_json(proj.path(), &api, &[]);
        assert_eq!(code, 0, "{env}");
        assert_eq!(hosted_events(&env), [pinned_event.clone()], "{env}");
        let (gemfile, lock) = (
            read(proj.path(), "Gemfile"),
            read(proj.path(), "Gemfile.lock"),
        );
        assert_eq!(gemfile, hosted_gemfile(&root));
        assert!(
            lock.starts_with(&format!(
                "GEM\n  remote: {root}\n  specs:\n    {DEP} ({DEP_VERSION})\n\nGEM\n"
            )),
            "{lock}"
        );
        assert!(
            lock.contains(&format!("  {DEP} ({DEP_VERSION}) sha256={RUBY_PATCHED}\n")),
            "{lock}"
        );

        // A reference with a snapshot URL and a list: nothing changes.
        server.reset().await;
        mount_api(&server, Some((&listed[..], 4))).await;
        let (code, env) = scan_json(proj.path(), &api, &[]);
        assert_eq!(code, 0, "{env}");
        assert_eq!(env["status"], "success", "{env}");
        assert_eq!(read(proj.path(), "Gemfile"), gemfile, "{platforms:?}");
        assert_eq!(read(proj.path(), "Gemfile.lock"), lock, "{platforms:?}");
        assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{env}");
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        assert_eq!(hosted_events(&env), [pinned_event.clone()], "{env}");
        let (references, other) = requests(&server).await;
        assert_eq!(references, [[UUID.to_string()]], "one reference request");
        assert_eq!(other, Vec::<String>::new(), "no registry request");
        let (code, stdout, stderr) = hosted(proj.path(), &api, &["scan"], &[]);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        assert!(
            stdout.contains("1 package is already on hosted patches; nothing to rewrite.\n"),
            "{stdout}"
        );
        assert!(!stderr.contains("Warning"), "{stderr}");
        assert_eq!(read(proj.path(), "Gemfile.lock"), lock);

        // A lock that is not pinned yet takes the same pair.
        let fresh = project(&ruby_lock(platforms));
        let (code, env) = scan_json(fresh.path(), &api, &[]);
        assert_eq!(code, 0, "{env}");
        assert_eq!(read(fresh.path(), "Gemfile"), gemfile, "{platforms:?}");
        assert_eq!(read(fresh.path(), "Gemfile.lock"), lock, "{platforms:?}");
        assert_eq!(hosted_events(&env), [pinned_event.clone()], "{env}");
    }
}

/// Under a patch mirror a run asks the mirror about each pin it is about
/// to write, and about none the project's files hold already. A gem the
/// lock names as its ruby-platform gem alone is pinned under the registry
/// without its snapshot level, and a run whose reference names the
/// registry at a snapshot knows that pin as its own: the second run asks
/// the mirror nothing and writes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_rerun_under_a_patch_mirror_knows_the_pin_without_a_snapshot() {
    const PREFIX: &str = "/artifactory/socket-patch";
    let listed: [Listed; 3] = [
        (ARM, ARM_PATCHED, Some(ARM_UUID)),
        ("ruby", RUBY_PATCHED, Some(UUID)),
        (LINUX, LINUX_UPSTREAM, None),
    ];
    let server = MockServer::start().await;
    mount_api(&server, Some((&listed[..], 4))).await;
    let api = server.uri();
    let mirror = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(path(format!(
            "{PREFIX}/patch/gem/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.gem"
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mirror)
        .await;
    let base = format!("{}{PREFIX}", mirror.uri());
    let root = registry_url(&base, UUID, None);
    let extra = ["--patch-mirror-url", base.as_str()];

    let proj = project(&ruby_lock(&["ruby"]));
    let (code, env) = scan_json(proj.path(), &api, &extra);
    assert_eq!(code, 0, "{env}");
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(read(proj.path(), "Gemfile"), hosted_gemfile(&root));
    let lock = read(proj.path(), "Gemfile.lock");
    assert!(
        lock.starts_with(&format!("GEM\n  remote: {root}\n  specs:\n")),
        "{lock}"
    );
    assert_eq!(
        mirror.received_requests().await.unwrap_or_default().len(),
        1,
        "the mirror is asked about the pin the run writes"
    );

    let (code, env) = scan_json(proj.path(), &api, &extra);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["redirect"]["rewrittenFiles"], json!([]), "{env}");
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(read(proj.path(), "Gemfile.lock"), lock);
    assert_eq!(
        mirror.received_requests().await.unwrap_or_default().len(),
        1,
        "a pin the project holds is not asked about again"
    );
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
