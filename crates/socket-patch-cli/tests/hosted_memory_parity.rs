//! Parity: the in-memory hosted engine over a file set produces the same
//! changed bytes, ledger bytes and `redirect` block as `scan --mode hosted
//! --json` over a checkout of the same files (the disk run goes through
//! the real binary under a scrubbed environment, so crawlers, host caches
//! and subprocesses contribute nothing on either side).

use std::collections::BTreeMap;

use base64::Engine;
use serde_json::Value;
use wiremock::MockServer;

#[path = "hosted_memory_common/mod.rs"]
mod common;

use common::*;

/// The core unit tests' env guard, compiled into this test binary too: the
/// engine runs in this process, and reads `SOCKET_NO_BAZEL` from it.
#[allow(dead_code)]
#[path = "../../socket-patch-core/src/test_env.rs"]
mod test_env;
use test_env::EnvGuard;

struct Case {
    /// Fixture dir under `crates/socket-patch-core/tests/fixtures/redirect`.
    fixture: &'static str,
    /// Extra files layered over the fixture input.
    extra: Vec<(&'static str, Vec<u8>)>,
    /// Require at least one redirect (a parity of two no-ops proves
    /// nothing for the formats the engine must rewrite).
    expect_redirect: bool,
    dry_run: bool,
    /// Serve a real tarball for every npm grant, its integrity rewritten
    /// to match: a yarn classic pin reads the served tarball (#558, #591),
    /// which the fixtures' placeholder hashes could never verify.
    serve_npm_tarballs: bool,
    /// Change the patches the fake API serves, for a case that differs from
    /// its fixture only in what the patch service answers.
    edit_patches: Option<fn(&mut [common::Patch])>,
}

fn case(fixture: &'static str) -> Case {
    Case {
        fixture,
        extra: Vec::new(),
        expect_redirect: true,
        dry_run: false,
        serve_npm_tarballs: false,
        edit_patches: None,
    }
}

/// For each npm patch: a minimal tarball (`package/package.json` naming
/// the package) served at its artifact URL, with the grant's sha512 and
/// sha1 set to that tarball's.
async fn serve_npm_tarballs(server: &MockServer, patches: &mut [common::Patch]) {
    use sha1::Digest as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    for patch in patches.iter_mut() {
        let Some(rest) = patch.purl.strip_prefix("pkg:npm/") else {
            continue;
        };
        let (name, version) = rest.rsplit_once('@').unwrap();
        let manifest = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", manifest.as_bytes())
            .unwrap();
        let tgz = builder.into_inner().unwrap().finish().unwrap();
        let url = patch.reference["url"].as_str().unwrap().to_string();
        let artifact = &mut patch.reference["artifacts"][0];
        artifact["integrity"]["sha512"] = Value::String(format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&tgz))
        ));
        artifact["integrity"]["sha1"] = Value::String(hex::encode(sha1::Sha1::digest(&tgz)));
        Mock::given(method("GET"))
            .and(path(url.strip_prefix(&server.uri()).unwrap().to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_raw(tgz, "application/octet-stream"))
            .mount(server)
            .await;
    }
}

/// Returns the (shared) `redirect` block so a case can assert on it too.
async fn assert_parity(case: Case) -> Value {
    assert_parity_run(case).await.0
}

/// [`assert_parity`], also returning the engine's result for the one root.
async fn assert_parity_run(case: Case) -> (Value, socket_patch_cli::hosted_memory::ProjectResult) {
    let dir = fixtures_root().join("redirect").join(case.fixture);
    let server = MockServer::start().await;
    let mut patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    if case.serve_npm_tarballs {
        serve_npm_tarballs(&server, &mut patches).await;
    }
    if let Some(edit) = case.edit_patches {
        edit(&mut patches);
    }
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("input"));
    for (rel, bytes) in &case.extra {
        files.insert((*rel).to_string(), bytes.clone());
    }
    let (name, dry_run, redirects) = (case.fixture, case.dry_run, case.expect_redirect);
    assert_parity_over(name, &server, &files, dry_run, redirects).await
}

/// The parity of the two engines over `files` against the patch API
/// `server` answers as: the shared `redirect` block and the engine's
/// result for the one root. `name` names the case in a failure, and
/// `expect_redirect` requires at least one redirect.
async fn assert_parity_over(
    name: &str,
    server: &MockServer,
    files: &BTreeMap<String, Vec<u8>>,
    dry_run: bool,
    expect_redirect: bool,
) -> (Value, socket_patch_cli::hosted_memory::ProjectResult) {
    let disk = run_disk(server, files, dry_run);
    let input = build_input(files, &[], options(dry_run));
    let memory = run_engine(server, input).await;

    assert_eq!(memory.projects.len(), 1, "{name}: one root");
    let project = &memory.projects[0];
    assert_eq!(project.root, "");
    assert!(project.error.is_none(), "{name}: {:?}", project.error);
    let disk_redirect = disk.redirect.clone();
    assert_eq!(
        sorted_redirect(&project.redirect),
        disk_redirect,
        "{name}: redirect block differs\nmemory: {:#}\ndisk: {:#}\nstderr: {}",
        project.redirect,
        disk_redirect,
        disk.stderr
    );
    let memory_changed = engine_changed(&memory);
    let expected_changed = if dry_run {
        assert!(
            disk.changed.is_empty(),
            "{name}: a disk dry run wrote files"
        );
        let mut wet = run_disk(server, files, false).changed;
        wet.remove(".socket/vendor/redirect-state.json");
        wet
    } else {
        disk.changed.clone()
    };
    assert_eq!(
        memory_changed.keys().collect::<Vec<_>>(),
        expected_changed.keys().collect::<Vec<_>>(),
        "{name}: changed file sets differ\nmemory:\n{}\ndisk:\n{}",
        describe(&memory_changed),
        describe(&expected_changed)
    );
    for (rel, bytes) in &expected_changed {
        assert_eq!(
            String::from_utf8_lossy(&memory_changed[rel]),
            String::from_utf8_lossy(bytes),
            "{name}: {rel} differs"
        );
    }
    let redirected = disk_redirect["redirected"].as_u64().unwrap_or(0);
    assert_eq!(redirected as usize, project.redirected.len());
    if expect_redirect {
        assert!(
            redirected > 0,
            "{name}: the fixture redirected nothing: {disk_redirect:#}\n{}",
            disk.stderr
        );
    }
    assert!(project.summary.scanned_packages >= redirected, "{name}");
    (disk_redirect, project.clone())
}

#[tokio::test]
async fn parity_package_lock() {
    assert_parity(case("npm/package-lock-v3/basic")).await;
}

#[tokio::test]
async fn parity_package_lock_dry_run() {
    assert_parity(Case {
        dry_run: true,
        ..case("npm/package-lock-v3/basic")
    })
    .await;
}

#[tokio::test]
async fn parity_pnpm_v9_trust_lockfile() {
    assert_parity(case("npm/pnpm/basic")).await;
}

#[tokio::test]
async fn parity_pnpm_existing_workspace() {
    assert_parity(Case {
        extra: vec![("pnpm-workspace.yaml", b"packages:\n  - 'apps/*'\n".to_vec())],
        ..case("npm/pnpm/basic")
    })
    .await;
}

#[tokio::test]
async fn parity_yarn_classic() {
    assert_parity(Case {
        serve_npm_tarballs: true,
        ..case("npm/yarn-classic/basic")
    })
    .await;
}

#[tokio::test]
async fn parity_yarn_berry() {
    assert_parity(case("npm/yarn-berry/basic")).await;
}

#[tokio::test]
async fn parity_bun_text_lock() {
    assert_parity(case("npm/bun/basic")).await;
}

#[tokio::test]
async fn parity_rush() {
    assert_parity(Case {
        extra: vec![
            ("rush.json", b"{}\n".to_vec()),
            ("common/config/rush/repo-state.json", b"{}\n".to_vec()),
        ],
        ..case("npm/pnpm/nested-rush-lock")
    })
    .await;
}

/// Rush subspaces keep a repo-state.json (the pnpmShrinkwrapHash carrier)
/// next to each subspace lock, and there is no common one (#714). Both the
/// disk run and the in-memory selector must see it, so both emit the
/// stale-hash warning; parity alone would pass with neither emitting it.
#[tokio::test]
async fn parity_rush_subspace() {
    let lock = std::fs::read(
        fixtures_root()
            .join("redirect/npm/pnpm/nested-rush-lock/input/common/config/rush/pnpm-lock.yaml"),
    )
    .unwrap();
    let redirect = assert_parity(Case {
        extra: vec![
            ("rush.json", b"{}\n".to_vec()),
            ("common/config/subspaces/x/pnpm-lock.yaml", lock),
            (
                "common/config/subspaces/x/repo-state.json",
                b"{}\n".to_vec(),
            ),
        ],
        ..case("npm/pnpm/nested-rush-lock")
    })
    .await;
    let codes: Vec<&str> = redirect["warnings"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        codes.contains(&"redirect_rush_repo_state_stale"),
        "a subspace repo-state.json must trigger the stale-hash warning; got {codes:?}"
    );
}

#[tokio::test]
async fn parity_uv() {
    assert_parity(Case {
        expect_redirect: false,
        ..case("pypi/uv/basic")
    })
    .await;
}

#[tokio::test]
async fn parity_requirements() {
    assert_parity(case("pypi/requirements/basic")).await;
}

#[tokio::test]
async fn parity_cargo() {
    assert_parity(case("cargo/cargo/basic")).await;
}

#[tokio::test]
async fn parity_cargo_workspace() {
    assert_parity(case("cargo/cargo/workspace-member")).await;
}

#[tokio::test]
async fn parity_composer() {
    assert_parity(case("composer/composer-lock/basic")).await;
}

#[tokio::test]
async fn parity_gemfile() {
    assert_parity(case("gem/bundler/basic")).await;
}

/// A gem the lock resolves only as precompiled platform builds. The lock
/// inventory has no ruby-platform entry to list it by, so both hosted
/// engines find it through the lock's platform specs (nothing is
/// installed here), and both move every build to its prebuild.
#[tokio::test]
async fn parity_gemfile_platform_prebuilds() {
    assert_parity(case("gem/bundler/platform-prebuilds")).await;
}

/// A lock of platform builds where the patch registry has a patched build
/// for one platform and serves upstream's own gem for the other. Both
/// engines move the gem, pin each build to what the registry serves, and
/// report it per locked build: the patched build under its own patch, the
/// other as kept on upstream's gem, counted by neither.
#[tokio::test]
async fn parity_gemfile_platform_pass_through() {
    use socket_patch_cli::hosted_memory::{RedirectedPatch, UpstreamBuild};
    const FIX: &str = "77777777-7777-7777-7777-777777777777";
    const LINUX: &str = "77777777-7777-4777-8777-00000000000b";
    let (redirect, project) = assert_parity_run(case("gem/bundler/platform-pass-through")).await;
    assert_eq!(redirect["redirected"], 1, "{redirect:#}");
    assert_eq!(redirect["warnings"], serde_json::json!([]), "{redirect:#}");
    assert_eq!(redirect["skipped"], serde_json::json!([]), "{redirect:#}");
    assert_eq!(
        redirect["patches"],
        serde_json::json!([
            {
                "purl": "pkg:gem/nokogiri@1.18.10?platform=arm64-darwin",
                "action": "upstream_kept",
                "errorCode": "gem_upstream_build_kept",
                "error": "the patch registry serves upstream's own gem for arm64-darwin: no \
                          patched build yet",
                "gemFix": FIX,
                "platform": "arm64-darwin",
            },
            {
                "purl": "pkg:gem/nokogiri@1.18.10?platform=x86_64-linux-gnu",
                "uuid": LINUX,
                "action": "pinned",
                "gemFix": FIX,
                "platform": "x86_64-linux-gnu",
                "newlyPatched": true,
            },
        ]),
        "{redirect:#}"
    );
    assert_eq!(
        project.redirected,
        [RedirectedPatch {
            purl: "pkg:gem/nokogiri@1.18.10?platform=x86_64-linux-gnu".into(),
            uuid: LINUX.into(),
            gem_fix: Some(FIX.into()),
            platform: Some("x86_64-linux-gnu".into()),
            newly_patched: true,
        }]
    );
    assert_eq!(
        project.upstream_builds,
        [UpstreamBuild {
            purl: "pkg:gem/nokogiri@1.18.10?platform=arm64-darwin".into(),
            gem_fix: FIX.into(),
            platform: "arm64-darwin".into(),
            withdrawn: false,
        }]
    );
    assert!(project.skipped.is_empty(), "{:?}", project.skipped);
}

/// A lock of platform builds on an earlier patch of the gem, whose patched
/// `arm64-darwin` build was withdrawn: the registry the lock is on no
/// longer lists it. The patch on offer serves upstream's gem for that
/// platform. Both engines ask the registry the lock is on, once each,
/// move the lock to the patch on offer with upstream's sha256 back for
/// that build, and report it as back on upstream's gem, in the same row.
#[tokio::test]
async fn parity_gemfile_platform_withdrawn_on_an_earlier_patch() {
    use socket_patch_cli::hosted_memory::UpstreamBuild;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    const TOKEN: &str = "11111111-1111-1111-1111-111111111111";
    const FIX: &str = "77777777-7777-7777-7777-777777777777";
    const LINUX: &str = "77777777-7777-4777-8777-00000000000b";
    const EARLIER: &str = "66666666-6666-4666-8666-666666666666";
    let dir = fixtures_root().join("redirect/gem/bundler/platform-pass-through");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    // The pair as a run left it on the earlier patch: the fixture's
    // hosted pair on this host, under the earlier patch and its snapshot,
    // with that patch's patched build pinned for `arm64-darwin`.
    let (upstream, withdrawn) = ("3".repeat(64), "a".repeat(64));
    let mut files = fixture_files(&dir.join("expected"));
    for bytes in files.values_mut() {
        let text = String::from_utf8(bytes.clone()).expect("a text fixture");
        let text = text
            .replace("https://patch.socket.dev", &server.uri())
            .replace(&format!("{FIX}/s/4/"), &format!("{EARLIER}/s/1a/"))
            .replace(&upstream, &withdrawn);
        *bytes = text.into_bytes();
    }
    let lock = String::from_utf8_lossy(&files["Gemfile.lock"]).into_owned();
    assert!(
        lock.contains(&format!("/{EARLIER}/s/1a/\n")) && lock.contains(&withdrawn),
        "premise: {lock}"
    );
    let index = format!("/patch-registry/gem/{TOKEN}/{EARLIER}/s/1a/info/nokogiri");
    Mock::given(method("GET"))
        .and(path(index.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "---\n1.18.10 racc:~> 1.4|checksum:{}\n1.18.10-x86_64-linux-gnu racc:~> \
             1.4|checksum:{}\n",
            "deadbeef".repeat(8),
            "b".repeat(64)
        )))
        .mount(&server)
        .await;

    let name = "a withdrawn build on an earlier patch";
    let (redirect, project) = assert_parity_over(name, &server, &files, false, true).await;
    assert_eq!(redirect["redirected"], 1, "{redirect:#}");
    assert_eq!(redirect["warnings"], serde_json::json!([]), "{redirect:#}");
    assert_eq!(redirect["skipped"], serde_json::json!([]), "{redirect:#}");
    assert_eq!(
        redirect["rewrittenFiles"],
        serde_json::json!(["Gemfile", "Gemfile.lock"])
    );
    assert_eq!(
        redirect["patches"],
        serde_json::json!([
            {
                "purl": "pkg:gem/nokogiri@1.18.10?platform=arm64-darwin",
                "action": "upstream_kept",
                "errorCode": "gem_upstream_build_kept",
                "error": "the patch registry serves upstream's own gem for arm64-darwin: its \
                          patched build was withdrawn",
                "gemFix": FIX,
                "platform": "arm64-darwin",
                "withdrawn": true,
            },
            {
                "purl": "pkg:gem/nokogiri@1.18.10?platform=x86_64-linux-gnu",
                "uuid": LINUX,
                "action": "pinned",
                "gemFix": FIX,
                "platform": "x86_64-linux-gnu",
            },
        ]),
        "{redirect:#}"
    );
    assert_eq!(
        project.upstream_builds,
        [UpstreamBuild {
            purl: "pkg:gem/nokogiri@1.18.10?platform=arm64-darwin".into(),
            gem_fix: FIX.into(),
            platform: "arm64-darwin".into(),
            withdrawn: true,
        }]
    );
    let asked = server.received_requests().await.unwrap_or_default();
    let asked = asked.iter().filter(|request| request.url.path() == index);
    assert_eq!(asked.count(), 2, "one request an engine");
}

/// A lock of platform builds stays on an earlier patch of the gem: the
/// patch on offer serves upstream's gem for `arm64-darwin`, which the
/// earlier patch still serves patched. The earlier patch withdrew its
/// `x86_64-linux-gnu` build, so its registry no longer lists it. Both
/// engines ask that registry once, ask the patch service for the earlier
/// patch's reference once, bring the lock to that patch's current
/// snapshot with upstream's sha256 back for the withdrawn build, and
/// report the same rows: the patch on offer skipped, one build in place
/// under its own patch, one back on upstream's gem.
#[tokio::test]
async fn parity_gemfile_platform_lock_that_stays_follows_its_own_patch() {
    use socket_patch_cli::hosted_memory::UpstreamBuild;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    const TOKEN: &str = "11111111-1111-1111-1111-111111111111";
    const FIX: &str = "77777777-7777-7777-7777-777777777777";
    const EARLIER: &str = "66666666-6666-4666-8666-666666666666";
    const EARLIER_ARM: &str = "66666666-6666-4666-8666-00000000000a";
    let dir = fixtures_root().join("redirect/gem/bundler/platform-pass-through");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    // The pair as a run left it on the earlier patch, which had a patched
    // build for both platforms.
    let (arm, linux, linux_upstream) = ("a".repeat(64), "c".repeat(64), "4".repeat(64));
    let mut files = fixture_files(&dir.join("expected"));
    for bytes in files.values_mut() {
        let text = String::from_utf8(bytes.clone()).expect("a text fixture");
        let text = text
            .replace("https://patch.socket.dev", &server.uri())
            .replace(&format!("{FIX}/s/4/"), &format!("{EARLIER}/s/1a/"))
            .replace(&"3".repeat(64), &arm)
            .replace(&"b".repeat(64), &linux);
        *bytes = text.into_bytes();
    }
    // The earlier patch's registry as the lock names it lists the ruby
    // gem and arm64-darwin, and no linux build.
    let registry = format!("/patch-registry/gem/{TOKEN}/{EARLIER}");
    let index = format!("{registry}/s/1a/info/nokogiri");
    Mock::given(method("GET"))
        .and(path(index.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "---\n1.18.10 racc:~> 1.4|checksum:{}\n1.18.10-arm64-darwin racc:~> \
             1.4|checksum:{arm}\n",
            "deadbeef".repeat(8)
        )))
        .mount(&server)
        .await;
    // The patch service answers a reference request with what it was asked
    // for: the patch on offer, and the earlier patch as it stands.
    let on_offer = patches[0].reference.clone();
    let earlier_now = serde_json::json!({
        "status": "granted",
        "url": format!("{}{registry}/gems/nokogiri-1.18.10.gem", server.uri()),
        "purl": "pkg:gem/nokogiri@1.18.10",
        "artifacts": [{"kind": "tarball", "url": null, "integrity": {
            "sha256": "deadbeef".repeat(8)
        }}],
        "registryOverride": {
            "kind": "rubygems-compact-index",
            "indexUrl": format!("{}{registry}/s/2b", server.uri()),
            "identifiers": {
                "name": "nokogiri", "version": "1.18.10",
                "gemChecksumSha256": "deadbeef".repeat(8),
                "gemBuilds": [
                    {"platform": "arm64-darwin", "gemChecksumSha256": arm,
                     "patchUuid": EARLIER_ARM},
                    {"platform": "x86_64-linux-gnu", "gemChecksumSha256": linux_upstream,
                     "patchUuid": null},
                ],
            },
        },
    });
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(move |request: &wiremock::Request| {
            let asked: Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let mut results = serde_json::Map::new();
            for uuid in asked["uuids"].as_array().into_iter().flatten() {
                match uuid.as_str() {
                    Some(FIX) => results.insert(FIX.to_string(), on_offer.clone()),
                    Some(EARLIER) => results.insert(EARLIER.to_string(), earlier_now.clone()),
                    _ => None,
                };
            }
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
        })
        .with_priority(1)
        .mount(&server)
        .await;

    let name = "a lock that stays follows its own patch";
    let (redirect, project) = assert_parity_over(name, &server, &files, false, true).await;
    assert_eq!(redirect["redirected"], 1, "{redirect:#}");
    assert_eq!(redirect["warnings"], serde_json::json!([]), "{redirect:#}");
    assert_eq!(
        redirect["rewrittenFiles"],
        serde_json::json!(["Gemfile", "Gemfile.lock"])
    );
    let waits = "nokogiri 1.18.10: the newer fix has no patched build for arm64-darwin yet; the \
                 lock stays on the patch it is on";
    assert_eq!(
        redirect["patches"],
        serde_json::json!([
            {
                "purl": "pkg:gem/nokogiri@1.18.10",
                "uuid": FIX,
                "action": "skipped",
                "errorCode": "redirect_gem_newer_fix_waits",
                "error": waits,
            },
            {
                "purl": "pkg:gem/nokogiri@1.18.10?platform=arm64-darwin",
                "uuid": EARLIER_ARM,
                "action": "pinned",
                "gemFix": EARLIER,
                "platform": "arm64-darwin",
            },
            {
                "purl": "pkg:gem/nokogiri@1.18.10?platform=x86_64-linux-gnu",
                "action": "upstream_kept",
                "errorCode": "gem_upstream_build_kept",
                "error": "the patch registry serves upstream's own gem for x86_64-linux-gnu: \
                          its patched build was withdrawn",
                "gemFix": EARLIER,
                "platform": "x86_64-linux-gnu",
                "withdrawn": true,
            },
        ]),
        "{redirect:#}"
    );
    assert_eq!(
        project.upstream_builds,
        [UpstreamBuild {
            purl: "pkg:gem/nokogiri@1.18.10?platform=x86_64-linux-gnu".into(),
            gem_fix: EARLIER.into(),
            platform: "x86_64-linux-gnu".into(),
            withdrawn: true,
        }]
    );
    let [skip] = project.skipped.as_slice() else {
        panic!("one skip: {:?}", project.skipped);
    };
    assert_eq!(
        (skip.uuid.as_str(), skip.reason.as_str()),
        (FIX, "redirect_gem_newer_fix_waits")
    );
    let asked = server.received_requests().await.unwrap_or_default();
    let indexes = asked.iter().filter(|request| request.url.path() == index);
    assert_eq!(indexes.count(), 2, "one registry request an engine");
    let references: Vec<Value> = asked
        .iter()
        .filter(|request| request.url.path().ends_with("/patches/package"))
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).unwrap_or_default()["uuids"].clone()
        })
        .collect();
    let per_engine = [serde_json::json!([FIX]), serde_json::json!([EARLIER])];
    assert_eq!(
        references,
        [&per_engine[..], &per_engine[..]].concat(),
        "each engine asks for the patch on offer, then once for the patch the lock is on"
    );
}

/// A lock with no `CHECKSUMS` on the patch's own registry, under an
/// earlier snapshot in which `x86_64-linux-gnu` was upstream's gem. Both
/// engines ask that snapshot what it lists, once each, move the lock to
/// the snapshot the reference names, and report the linux build as newly
/// patched and `arm64-darwin` as upstream's gem.
#[tokio::test]
async fn parity_gemfile_platform_newer_snapshot_without_checksums() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    const TOKEN: &str = "11111111-1111-1111-1111-111111111111";
    const FIX: &str = "77777777-7777-7777-7777-777777777777";
    const LINUX: &str = "77777777-7777-4777-8777-00000000000b";
    let dir = fixtures_root().join("redirect/gem/bundler/platform-pass-through");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("expected"));
    for bytes in files.values_mut() {
        let text = String::from_utf8(bytes.clone()).expect("a text fixture");
        let mut text = text
            .replace("https://patch.socket.dev", &server.uri())
            .replace(&format!("{FIX}/s/4/"), &format!("{FIX}/s/1a/"));
        if let (Some(at), Some(end)) = (text.find("CHECKSUMS\n"), text.find("BUNDLED WITH")) {
            text.replace_range(at..end, "");
        }
        *bytes = text.into_bytes();
    }
    let lock = String::from_utf8_lossy(&files["Gemfile.lock"]).into_owned();
    assert!(
        lock.contains(&format!("/{FIX}/s/1a/\n")) && !lock.contains("CHECKSUMS"),
        "premise: {lock}"
    );
    let index = format!("/patch-registry/gem/{TOKEN}/{FIX}/s/1a/info/nokogiri");
    Mock::given(method("GET"))
        .and(path(index.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "---\n1.18.10 racc:~> 1.4|checksum:{}\n1.18.10-arm64-darwin racc:~> \
             1.4|checksum:{}\n1.18.10-x86_64-linux-gnu racc:~> 1.4|checksum:{}\n",
            "deadbeef".repeat(8),
            "3".repeat(64),
            "4".repeat(64)
        )))
        .mount(&server)
        .await;

    let name = "a newer snapshot on a lock without CHECKSUMS";
    let (redirect, project) = assert_parity_over(name, &server, &files, false, true).await;
    assert_eq!(redirect["redirected"], 1, "{redirect:#}");
    let codes: Vec<&str> = redirect["warnings"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(codes, ["redirect_gem_no_checksums_section"], "{redirect:#}");
    assert_eq!(
        redirect["patches"],
        serde_json::json!([
            {
                "purl": "pkg:gem/nokogiri@1.18.10?platform=arm64-darwin",
                "action": "upstream_kept",
                "errorCode": "gem_upstream_build_kept",
                "error": "the patch registry serves upstream's own gem for arm64-darwin: no \
                          patched build yet",
                "gemFix": FIX,
                "platform": "arm64-darwin",
            },
            {
                "purl": "pkg:gem/nokogiri@1.18.10?platform=x86_64-linux-gnu",
                "uuid": LINUX,
                "action": "pinned",
                "gemFix": FIX,
                "platform": "x86_64-linux-gnu",
                "newlyPatched": true,
            },
        ]),
        "{redirect:#}"
    );
    assert!(
        project.redirected[0].newly_patched,
        "{:?}",
        project.redirected
    );
    let asked = server.received_requests().await.unwrap_or_default();
    let indexes = asked.iter().filter(|request| request.url.path() == index);
    assert_eq!(indexes.count(), 2, "one request an engine");
}

/// The same lock where no locked platform has a patched build yet: both
/// engines leave the gem on its upstream registry, write nothing, warn of
/// nothing, and report one skip under the quiet code, never an unpinned
/// patch.
#[tokio::test]
async fn parity_gemfile_platform_no_patched_build() {
    fn none_patched(patches: &mut [common::Patch]) {
        for patch in patches {
            let builds = &mut patch.reference["registryOverride"]["identifiers"]["gemBuilds"];
            for build in builds.as_array_mut().expect("the fixture lists builds") {
                build["patchUuid"] = Value::Null;
            }
        }
    }
    let (redirect, project) = assert_parity_run(Case {
        expect_redirect: false,
        edit_patches: Some(none_patched),
        ..case("gem/bundler/platform-pass-through")
    })
    .await;
    let detail = "nokogiri 1.18.10: no patched build yet for arm64-darwin, x86_64-linux-gnu; left \
                  on its upstream registry";
    assert_eq!(redirect["redirected"], 0, "{redirect:#}");
    assert_eq!(redirect["rewrittenFiles"], serde_json::json!([]));
    assert_eq!(redirect["warnings"], serde_json::json!([]), "{redirect:#}");
    assert_eq!(
        redirect["patches"],
        serde_json::json!([{
            "purl": "pkg:gem/nokogiri@1.18.10",
            "uuid": "77777777-7777-7777-7777-777777777777",
            "action": "skipped",
            "errorCode": "redirect_gem_no_patched_build",
            "error": detail,
        }]),
        "{redirect:#}"
    );
    assert!(project.redirected.is_empty() && project.upstream_builds.is_empty());
    let [skip] = project.skipped.as_slice() else {
        panic!("one skip: {:?}", project.skipped);
    };
    assert_eq!(skip.reason, "redirect_gem_no_patched_build");
    assert_eq!(skip.detail.as_deref(), Some(detail));
}

/// The gem fixture as the root of a Bazel workspace whose rules_ruby hub
/// reads the lock and names the patched gem in `gem_checksums`. With the
/// sha256 of the upstream archive there, the checkout and the engine write
/// no file and say why in the same words. With the one of the patched
/// archive both write what they write without Bazel. The engine is given
/// the files that path selection asks for. It judges the hub unless
/// `SOCKET_NO_BAZEL` is set, so the test holds the variable unset.
#[tokio::test]
#[serial_test::serial]
async fn parity_gem_checksums_of_a_bazel_hub_through_selection() {
    let _unset = EnvGuard::unset("SOCKET_NO_BAZEL");
    let dir = fixtures_root().join("redirect/gem/bundler/basic");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("input"));
    let plain = run_disk(&server, &files, false);
    assert!(
        plain.changed.contains_key("Gemfile.lock"),
        "{}",
        plain.stderr
    );
    let code = "redirect_bazel_gem_checksums_pinned";
    for (sum, left) in [("2".repeat(64), true), ("deadbeef".repeat(8), false)] {
        let module = format!(
            "bazel_dep(name = \"rules_ruby\", version = \"1.0.0-rc2\")\n\
             ruby = use_extension(\"@rules_ruby//ruby:extensions.bzl\", \"ruby\")\n\
             ruby.bundle_fetch(\n    name = \"bundle\",\n    gemfile = \"//:Gemfile\",\n    \
             gemfile_lock = \"//:Gemfile.lock\",\n    gem_checksums = {{\"rails-7.0.0\": \
             \"{sum}\"}},\n)\n"
        );
        files.insert("MODULE.bazel".into(), module.into_bytes());
        let disk = run_disk(&server, &files, false);
        let memory = run_engine(&server, selected_input(&files)).await;
        let project = &memory.projects[0];
        assert!(project.error.is_none(), "{:?}", project.error);
        assert_eq!(
            sorted_redirect(&project.redirect),
            disk.redirect,
            "{}",
            disk.stderr
        );
        assert_eq!(engine_changed(&memory), disk.changed, "{}", disk.stderr);
        let warnings = disk.redirect["warnings"].as_array().unwrap();
        let said: Vec<&str> = warnings
            .iter()
            .filter(|warning| warning["code"] == code)
            .filter_map(|warning| warning["detail"].as_str())
            .collect();
        if left {
            assert_eq!(disk.changed.len(), 0, "{}", disk.stderr);
            assert_eq!(said.len(), 1, "{:#}", disk.redirect);
            let named = "rails@7.0.0: `ruby.bundle_fetch` at MODULE.bazel:3 holds `rails-7.0.0`";
            assert!(said[0].starts_with(named), "{}", said[0]);
            assert_eq!(disk.redirect["patches"][0]["action"], "unpinned");
        } else {
            assert_eq!(disk.changed, plain.changed, "{}", disk.stderr);
            assert_eq!(disk.redirect, plain.redirect, "{}", disk.stderr);
        }
    }
}

#[tokio::test]
async fn parity_golang() {
    assert_parity(case("golang/gomod/basic")).await;
}

/// Formats with no golden redirect fixture: a committed native lock plus a
/// synthetic override for one of its packages.
async fn assert_native_parity(
    files: BTreeMap<String, Vec<u8>>,
    overrides: Value,
    expect_redirect: bool,
) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("overrides.json"), overrides.to_string()).unwrap();
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&tmp.path().join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let disk = run_disk(&server, &files, false);
    let memory = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &memory.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert_eq!(
        without_pipenv_advice(&sorted_redirect(&project.redirect)),
        without_pipenv_advice(&disk.redirect),
        "{}",
        disk.stderr
    );
    let memory_changed = engine_changed(&memory);
    assert_eq!(
        memory_changed,
        disk.changed,
        "memory:\n{}\ndisk:\n{}",
        describe(&memory_changed),
        describe(&disk.changed)
    );
    if expect_redirect {
        assert!(!project.redirected.is_empty(), "{:#}", project.redirect);
    }
}

/// The in-memory engine cannot find Pipenv on PATH, so its
/// `redirect_pipenv_installer_unknown` advice names the `pipenvMajor`
/// option instead of the disk run's PATH/env remedy.
fn without_pipenv_advice(redirect: &Value) -> Value {
    let mut redirect = redirect.clone();
    if let Some(warnings) = redirect.get_mut("warnings").and_then(Value::as_array_mut) {
        for warning in warnings.iter_mut() {
            if warning["code"] == "redirect_pipenv_installer_unknown" {
                warning["detail"] = Value::Null;
            }
        }
    }
    redirect
}

fn read_fixture(rel: &str) -> Vec<u8> {
    std::fs::read(fixtures_root().join(rel)).unwrap()
}

#[tokio::test]
async fn parity_poetry() {
    let files = BTreeMap::from([
        (
            "poetry.lock".to_string(),
            read_fixture("poetry/2.4.3/poetry.lock"),
        ),
        (
            "pyproject.toml".to_string(),
            read_fixture("poetry/2.4.3/pyproject.toml"),
        ),
    ]);
    let overrides = serde_json::json!([{
        "ecosystem": "pypi", "name": "urllib3", "version": "1.26.18",
        "token": "22222222-2222-4222-8222-222222222222",
        "patchUuid": "e828efa5-5c6d-43f3-9909-03f5ac232b98",
        "artifactUrl": "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl",
        "integrity": {"sha256": "c".repeat(64)}
    }]);
    assert_native_parity(files, overrides, true).await;
}

#[tokio::test]
async fn parity_pipfile() {
    let files = BTreeMap::from([
        (
            "Pipfile.lock".to_string(),
            read_fixture("pipenv/2026.8.0/Pipfile.lock"),
        ),
        (
            "Pipfile".to_string(),
            read_fixture("pipenv/2026.8.0/Pipfile"),
        ),
    ]);
    let lock: Value = serde_json::from_slice(&files["Pipfile.lock"]).unwrap();
    let (name, entry) = lock["default"]
        .as_object()
        .and_then(|m| m.iter().next())
        .expect("a default package");
    let version = entry["version"].as_str().unwrap().trim_start_matches("==");
    let overrides = serde_json::json!([{
        "ecosystem": "pypi", "name": name, "version": version,
        "token": "22222222-2222-4222-8222-222222222222",
        "patchUuid": "e828efa5-5c6d-43f3-9909-03f5ac232b98",
        "artifactUrl": format!("https://patch.socket.dev/patch/pypi/{name}/{version}/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/{name}-{version}-py3-none-any.whl"),
        "integrity": {"sha256": "c".repeat(64)}
    }]);
    assert_native_parity(files, overrides, true).await;
}

#[tokio::test]
async fn parity_bun_binary_lock() {
    let files = BTreeMap::from([
        (
            "bun.lockb".to_string(),
            read_fixture("bun-lockb/1.1.45/bun.lockb"),
        ),
        (
            "package.json".to_string(),
            read_fixture("bun-lockb/1.1.45/package.json"),
        ),
    ]);
    let overrides = serde_json::json!([{
        "ecosystem": "npm", "name": "minimist", "version": "1.2.2",
        "token": "22222222-2222-4222-8222-222222222222",
        "patchUuid": "33333333-3333-4333-8333-333333333333",
        "artifactUrl": "https://patch.socket.dev/patch/npm/minimist/1.2.2/22222222-2222-4222-8222-222222222222/33333333-3333-4333-8333-333333333333/minimist-1.2.2.tgz",
        "integrity": {"sha512": format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode([0x5au8; 64])
        )}
    }]);
    assert_native_parity(files, overrides, true).await;
}

#[tokio::test]
async fn parity_nested_monorepo_roots_match_their_own_disk_runs() {
    let npm = fixtures_root().join("redirect/npm/package-lock-v3/basic");
    let cargo = fixtures_root().join("redirect/cargo/cargo/basic");
    let server = MockServer::start().await;
    let mut patches = patches_from_overrides(&npm.join("overrides.json"), None);
    patches.extend(patches_from_overrides(&cargo.join("overrides.json"), None));
    mount_api(&server, &patches).await;
    let web = fixture_files(&npm.join("input"));
    let svc = fixture_files(&cargo.join("input"));
    let mut repo: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (rel, bytes) in &web {
        repo.insert(format!("apps/web/{rel}"), bytes.clone());
    }
    for (rel, bytes) in &svc {
        repo.insert(format!("services/api/{rel}"), bytes.clone());
    }
    let memory = run_engine(&server, build_input(&repo, &[], options(false))).await;
    let roots: Vec<&str> = memory.projects.iter().map(|p| p.root.as_str()).collect();
    assert_eq!(roots, vec!["apps/web", "services/api"]);
    let changed = engine_changed(&memory);
    for (root, files) in [("apps/web", &web), ("services/api", &svc)] {
        let disk = run_disk(&server, files, false);
        let project = memory.projects.iter().find(|p| p.root == root).unwrap();
        assert_eq!(sorted_redirect(&project.redirect), disk.redirect, "{root}");
        let prefixed: BTreeMap<String, Vec<u8>> = changed
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix(&format!("{root}/"))
                    .map(|rel| (rel.to_string(), v.clone()))
            })
            .collect();
        assert_eq!(prefixed, disk.changed, "{root}");
    }
}

fn wheel(name: &str, version: &str) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(format!("{name}-{version}.dist-info/METADATA"), options)
            .unwrap();
        write!(
            zip,
            "Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n"
        )
        .unwrap();
        zip.finish().unwrap();
    }
    buf.into_inner()
}

#[tokio::test]
async fn parity_uv_with_hosted_wheel_metadata() {
    use sha2::Digest;
    let dir = fixtures_root().join("redirect/pypi/uv/basic");
    let server = MockServer::start().await;
    let bytes = wheel("click", "8.1.7");
    let sha = hex::encode(sha2::Sha256::digest(&bytes));
    let tmp = tempfile::tempdir().unwrap();
    let mut overrides: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("overrides.json")).unwrap())
            .unwrap();
    overrides[0]["integrity"]["sha256"] = Value::String(sha);
    std::fs::write(tmp.path().join("overrides.json"), overrides.to_string()).unwrap();
    let patches = patches_from_overrides(&tmp.path().join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path_regex("^/patch/pypi/.+\\.whl$"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(&server)
        .await;
    let files = fixture_files(&dir.join("input"));
    let disk = run_disk(&server, &files, false);
    let memory = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &memory.projects[0];
    assert_eq!(
        sorted_redirect(&project.redirect),
        disk.redirect,
        "{}",
        disk.stderr
    );
    assert_eq!(engine_changed(&memory), disk.changed);
    assert_eq!(project.redirected.len(), 1, "{:#}", project.redirect);
    assert_eq!(
        memory.stats.provider_calls.get("downloadArtifact"),
        Some(&1)
    );
}

/// `files` narrowed to what [`select_paths`] asks the host to stream
/// (presence-only paths marked present), so the parity covers selection.
fn selected_input(
    files: &BTreeMap<String, Vec<u8>>,
) -> socket_patch_cli::hosted_memory::HostedScanInput {
    use socket_patch_cli::hosted_memory::{select_paths, SelectOptions, TreeEntryInput};
    let entries: Vec<TreeEntryInput> = files
        .iter()
        .map(|(p, bytes)| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(bytes.len() as u64),
        })
        .collect();
    let selection = select_paths(&entries, &SelectOptions::default());
    let fetched: BTreeMap<String, Vec<u8>> = selection
        .fetch_text
        .iter()
        .chain(selection.fetch_binary.iter())
        .map(|p| (p.clone(), files[p].clone()))
        .collect();
    let present: Vec<&str> = selection.present_only.iter().map(String::as_str).collect();
    let mut opts = options(false);
    opts.project_roots = Some(selection.roots.clone());
    build_input(&fetched, &present, opts)
}

#[tokio::test]
async fn parity_cargo_patch_path_under_vendor_through_selection() {
    let dir = fixtures_root().join("redirect/cargo/cargo/workspace-member");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("input"));
    let mut manifest = String::from_utf8(files["Cargo.toml"].clone()).unwrap();
    manifest.push_str("\n[patch.crates-io]\nfoo = { path = \"vendor/foo\" }\n");
    files.insert("Cargo.toml".into(), manifest.into_bytes());
    let mut lock = String::from_utf8(files["Cargo.lock"].clone()).unwrap();
    lock.push_str(
        "\n[[package]]\nname = \"foo\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n]\n",
    );
    files.insert("Cargo.lock".into(), lock.into_bytes());
    files.insert(
        "vendor/foo/Cargo.toml".into(),
        b"[package]\nname = \"foo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n"
            .to_vec(),
    );
    files.insert(
        "tests/fixtures/other/Cargo.toml".into(),
        b"[package]\nname = \"other\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n"
            .to_vec(),
    );

    let disk = run_disk(&server, &files, false);
    assert!(
        disk.changed.contains_key("vendor/foo/Cargo.toml"),
        "disk pins the [patch] path crate: {}\n{}",
        describe(&disk.changed),
        disk.stderr
    );
    let memory = run_engine(&server, selected_input(&files)).await;
    let project = &memory.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert_eq!(
        sorted_redirect(&project.redirect),
        disk.redirect,
        "{}",
        disk.stderr
    );
    let memory_changed = engine_changed(&memory);
    assert_eq!(
        memory_changed,
        disk.changed,
        "memory:\n{}\ndisk:\n{}",
        describe(&memory_changed),
        describe(&disk.changed)
    );
    assert_eq!(project.redirected.len(), 1, "{:#}", project.redirect);
}

/// `cargo vendor` output (`.cargo-checksum.json` in every crate) sits under
/// `vendor/` with a `[patch]`-free workspace: disk never reads it, and
/// selection must not fetch it either.
fn with_cargo_vendor_tree(files: &mut BTreeMap<String, Vec<u8>>) {
    for krate in ["serde", "itoa"] {
        files.insert(
            format!("vendor/{krate}/Cargo.toml"),
            format!("[package]\nname = \"{krate}\"\nversion = \"1.0.190\"\n").into_bytes(),
        );
        files.insert(
            format!("vendor/{krate}/.cargo-checksum.json"),
            b"{\"files\":{},\"package\":\"00\"}".to_vec(),
        );
        files.insert(
            format!("vendor/{krate}/tests/ui/Cargo.toml"),
            b"[package]\nname = \"ui\"\nversion = \"0.0.0\"\n".to_vec(),
        );
    }
}

fn selected_paths(files: &BTreeMap<String, Vec<u8>>) -> Vec<String> {
    use socket_patch_cli::hosted_memory::{select_paths, SelectOptions, TreeEntryInput};
    let entries: Vec<TreeEntryInput> = files
        .keys()
        .map(|p| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(1),
        })
        .collect();
    let selection = select_paths(&entries, &SelectOptions::default());
    selection
        .fetch_text
        .into_iter()
        .chain(selection.fetch_binary)
        .chain(selection.present_only)
        .collect()
}

#[tokio::test]
async fn parity_cargo_vendor_tree_is_not_fetched() {
    let dir = fixtures_root().join("redirect/cargo/cargo/workspace-member");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("input"));
    with_cargo_vendor_tree(&mut files);

    let selected = selected_paths(&files);
    assert!(
        !selected.iter().any(|p| p.starts_with("vendor/")),
        "{selected:?}"
    );
    let disk = run_disk(&server, &files, false);
    assert!(
        !disk.changed.keys().any(|p| p.starts_with("vendor/")),
        "{}",
        describe(&disk.changed)
    );
    let memory = run_engine(&server, selected_input(&files)).await;
    let project = &memory.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert_eq!(
        sorted_redirect(&project.redirect),
        disk.redirect,
        "{}",
        disk.stderr
    );
    let memory_changed = engine_changed(&memory);
    assert_eq!(
        memory_changed,
        disk.changed,
        "memory:\n{}\ndisk:\n{}",
        describe(&memory_changed),
        describe(&disk.changed)
    );
    assert!(!project.redirected.is_empty(), "{:#}", project.redirect);
}

#[tokio::test]
async fn cargo_patch_path_into_vendor_tree_fails_closed() {
    let dir = fixtures_root().join("redirect/cargo/cargo/workspace-member");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("input"));
    let mut manifest = String::from_utf8(files["Cargo.toml"].clone()).unwrap();
    manifest.push_str("\n[patch.crates-io]\nfoo = { path = \"vendor/foo\" }\n");
    files.insert("Cargo.toml".into(), manifest.into_bytes());
    let mut lock = String::from_utf8(files["Cargo.lock"].clone()).unwrap();
    lock.push_str(
        "\n[[package]]\nname = \"foo\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n]\n",
    );
    files.insert("Cargo.lock".into(), lock.into_bytes());
    files.insert(
        "vendor/foo/Cargo.toml".into(),
        b"[package]\nname = \"foo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n"
            .to_vec(),
    );
    files.insert(
        "vendor/foo/.cargo-checksum.json".into(),
        b"{\"files\":{},\"package\":\"00\"}".to_vec(),
    );

    let memory = run_engine(&server, selected_input(&files)).await;
    let project = &memory.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert!(project.redirected.is_empty(), "{:#}", project.redirect);
    assert!(
        engine_changed(&memory).is_empty(),
        "{}",
        describe(&engine_changed(&memory))
    );
    assert!(
        project
            .redirect
            .to_string()
            .contains("redirect_cargo_transitive_dependents"),
        "{:#}",
        project.redirect
    );
}

#[tokio::test]
async fn pipfile_advice_names_the_pipenv_major_option() {
    let files = BTreeMap::from([
        (
            "Pipfile.lock".to_string(),
            read_fixture("pipenv/2026.8.0/Pipfile.lock"),
        ),
        (
            "Pipfile".to_string(),
            read_fixture("pipenv/2026.8.0/Pipfile"),
        ),
    ]);
    let lock: Value = serde_json::from_slice(&files["Pipfile.lock"]).unwrap();
    let (name, entry) = lock["default"]
        .as_object()
        .and_then(|m| m.iter().next())
        .expect("a default package");
    let version = entry["version"].as_str().unwrap().trim_start_matches("==");
    let overrides = serde_json::json!([{
        "ecosystem": "pypi", "name": name, "version": version,
        "token": "22222222-2222-4222-8222-222222222222",
        "patchUuid": "e828efa5-5c6d-43f3-9909-03f5ac232b98",
        "artifactUrl": format!("https://patch.socket.dev/patch/pypi/{name}/{version}/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/{name}-{version}-py3-none-any.whl"),
        "integrity": {"sha256": "c".repeat(64)}
    }]);
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("overrides.json"), overrides.to_string()).unwrap();
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&tmp.path().join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let memory = run_engine(&server, build_input(&files, &[], options(false))).await;
    let detail = memory.projects[0].redirect["warnings"]
        .as_array()
        .and_then(|w| {
            w.iter()
                .find(|x| x["code"] == "redirect_pipenv_installer_unknown")
        })
        .and_then(|w| w["detail"].as_str())
        .expect("pipenv advice warning")
        .to_string();
    assert!(detail.contains("`pipenvMajor`"), "{detail}");
    assert!(!detail.contains("PATH"), "{detail}");
}

#[tokio::test]
async fn excluded_nested_cargo_project_is_its_own_root_through_selection() {
    let ws = fixtures_root().join("redirect/cargo/cargo/workspace-member");
    let standalone = fixtures_root().join("redirect/cargo/cargo/basic");
    let server = MockServer::start().await;
    let mut patches = patches_from_overrides(&ws.join("overrides.json"), Some(&server.uri()));
    patches.extend(patches_from_overrides(
        &standalone.join("overrides.json"),
        Some(&server.uri()),
    ));
    mount_api(&server, &patches).await;

    let mut repo = fixture_files(&ws.join("input"));
    let manifest = String::from_utf8(repo["Cargo.toml"].clone())
        .unwrap()
        .replacen(
            "[workspace]\n",
            "[workspace]\nexclude = [\"tools/fuzz\"]\n",
            1,
        );
    repo.insert("Cargo.toml".into(), manifest.into_bytes());
    let stale_member_lock = repo["Cargo.lock"].clone();
    repo.insert("a/Cargo.lock".into(), stale_member_lock);
    let fuzz = fixture_files(&standalone.join("input"));
    for (rel, bytes) in &fuzz {
        repo.insert(format!("tools/fuzz/{rel}"), bytes.clone());
    }

    let memory = run_engine(&server, selected_input(&repo)).await;
    let roots: Vec<&str> = memory.projects.iter().map(|p| p.root.as_str()).collect();
    assert!(roots.contains(&"tools/fuzz"), "{roots:?}");
    let changed = engine_changed(&memory);

    let disk = run_disk(&server, &fuzz, false);
    let fuzz_project = memory
        .projects
        .iter()
        .find(|p| p.root == "tools/fuzz")
        .unwrap();
    assert!(fuzz_project.error.is_none(), "{:?}", fuzz_project.error);
    assert_eq!(sorted_redirect(&fuzz_project.redirect), disk.redirect);
    let fuzz_changed: BTreeMap<String, Vec<u8>> = changed
        .iter()
        .filter_map(|(k, v)| {
            k.strip_prefix("tools/fuzz/")
                .map(|rel| (rel.to_string(), v.clone()))
        })
        .collect();
    assert_eq!(fuzz_changed, disk.changed);
    assert!(
        !fuzz_project.redirected.is_empty(),
        "{:#}",
        fuzz_project.redirect
    );

    let workspace = memory.projects.iter().find(|p| p.root.is_empty()).unwrap();
    assert!(!workspace.redirected.is_empty(), "{:#}", workspace.redirect);
    assert!(
        !changed.contains_key("a/Cargo.lock"),
        "{}",
        describe(&changed)
    );
    assert!(
        memory.warnings.iter().any(
            |w| w.code == "cargo_member_lock_ignored" && w.project_root.as_deref() == Some("a")
        ),
        "{:?}",
        memory.warnings
    );
}

/// A three-root repo with a root socket.yml: two copies of the npm
/// fixture and the cargo fixture.
fn policy_repo(socket_yml: &str) -> (Vec<Patch>, BTreeMap<String, Vec<u8>>) {
    let npm = fixtures_root().join("redirect/npm/package-lock-v3/basic");
    let cargo = fixtures_root().join("redirect/cargo/cargo/basic");
    let mut patches = patches_from_overrides(&npm.join("overrides.json"), None);
    patches.extend(patches_from_overrides(&cargo.join("overrides.json"), None));
    let mut repo: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (root, dir) in [
        ("apps/web", &npm),
        ("apps/legacy", &npm),
        ("services/api", &cargo),
    ] {
        for (rel, bytes) in fixture_files(&dir.join("input")) {
            repo.insert(format!("{root}/{rel}"), bytes);
        }
    }
    repo.insert("socket.yml".to_string(), socket_yml.as_bytes().to_vec());
    (patches, repo)
}

/// The host's two-phase flow: fetch the root policy files, select with
/// their text, stream what selection asks for (presence-only paths marked
/// present) and pass selection's policy outputs to the session.
fn two_phase(
    files: &BTreeMap<String, Vec<u8>>,
    mut opts: socket_patch_cli::hosted_memory::HostedScanOptions,
) -> (
    socket_patch_cli::hosted_memory::PathSelection,
    socket_patch_cli::hosted_memory::HostedScanInput,
) {
    use socket_patch_cli::hosted_memory::{
        select_paths, PolicyFileInput, SelectOptions, TreeEntryInput,
    };
    let entries: Vec<TreeEntryInput> = files
        .iter()
        .map(|(p, bytes)| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(bytes.len() as u64),
        })
        .collect();
    let policy_files: Vec<PolicyFileInput> = ["socket.yml", "socket.yaml"]
        .iter()
        .filter_map(|name| {
            files.get(*name).map(|bytes| PolicyFileInput {
                path: name.to_string(),
                text: Some(String::from_utf8(bytes.clone()).unwrap()),
                missing: None,
            })
        })
        .collect();
    let selection = select_paths(
        &entries,
        &SelectOptions {
            policy_files: Some(policy_files),
            no_socket_yml: opts.no_socket_yml,
            ..SelectOptions::default()
        },
    );
    let fetched: BTreeMap<String, Vec<u8>> = selection
        .fetch_text
        .iter()
        .chain(selection.fetch_binary.iter())
        .map(|p| (p.clone(), files[p].clone()))
        .collect();
    let present: Vec<&str> = selection.present_only.iter().map(String::as_str).collect();
    opts.policy_paths = Some(selection.policy_paths.clone());
    opts.policy_sha256 = selection.policy_sha256.clone();
    let input = build_input(&fetched, &present, opts);
    (selection, input)
}

fn policy_input(
    files: &BTreeMap<String, Vec<u8>>,
) -> socket_patch_cli::hosted_memory::HostedScanInput {
    let (selection, input) = two_phase(files, options(false));
    assert!(
        selection.policy_error.is_none(),
        "{:?}",
        selection.policy_error
    );
    input
}

/// Session options as selection of `files` would hand them over, without
/// going through selection (for inputs a host may get wrong).
fn policy_options(
    files: &BTreeMap<String, Vec<u8>>,
) -> socket_patch_cli::hosted_memory::HostedScanOptions {
    let (selection, _) = two_phase(files, options(false));
    let mut opts = options(false);
    opts.policy_paths = Some(selection.policy_paths);
    opts.policy_sha256 = selection.policy_sha256;
    opts
}

/// `(project, purl, reason)` of a `policy.filtered[]` list.
fn filtered_set(policy: &Value) -> std::collections::BTreeSet<(String, Option<String>, String)> {
    policy["filtered"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["project"].as_str().unwrap().to_string(),
                f["purl"].as_str().map(str::to_string),
                f["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[tokio::test]
async fn parity_socket_yml_filters_the_same_roots_and_packages() {
    let (patches, repo) = policy_repo(
        "version: 2\npatches:\n  ignorePaths: [\"/apps/legacy/\"]\n  ignorePackages: [\"pkg:cargo/serde\"]\n",
    );
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let (selection, input) = two_phase(&repo, options(false));
    assert!(
        selection.policy_error.is_none(),
        "{:?}",
        selection.policy_error
    );
    let memory = run_engine(&server, input).await;
    assert!(memory.policy_error.is_none(), "{:?}", memory.policy_error);
    let roots: Vec<&str> = memory.projects.iter().map(|p| p.root.as_str()).collect();
    assert_eq!(
        roots,
        vec!["apps/web", "services/api"],
        "the ignored root is not processed"
    );
    // Selection reports the root it excluded; nothing of it is streamed.
    assert!(selection
        .ignored_sample
        .iter()
        .any(|i| i.path == "apps/legacy/package-lock.json" && i.reason == "policy_path_excluded"));
    assert!(!selection
        .fetch_text
        .iter()
        .chain(&selection.present_only)
        .any(|p| p.starts_with("apps/legacy/")));
    let memory_policy = memory.policy.clone().expect("policy block");
    assert_eq!(memory_policy["source"], "file");

    let mut disk_filtered = std::collections::BTreeSet::new();
    for root in ["apps/web", "apps/legacy", "services/api"] {
        let disk = run_disk_in(&server, &repo, root, false);
        assert_eq!(
            disk.envelope["status"], "success",
            "{root}: {}",
            disk.stderr
        );
        assert_eq!(
            disk.envelope["policy"]["sha256"], memory_policy["sha256"],
            "{root}"
        );
        disk_filtered.extend(filtered_set(&disk.envelope["policy"]));
        if let Some(project) = memory.projects.iter().find(|p| p.root == root) {
            assert_eq!(sorted_redirect(&project.redirect), disk.redirect, "{root}");
            let prefix = format!("{root}/");
            let memory_changed: BTreeMap<String, Vec<u8>> = engine_changed(&memory)
                .into_iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .collect();
            assert_eq!(memory_changed, disk.changed, "{root}");
        } else {
            assert!(
                disk.changed.is_empty(),
                "{root}: an ignored root changes nothing"
            );
        }
    }
    let mut memory_filtered = filtered_set(&memory_policy);
    memory_filtered.insert((
        "apps/legacy".to_string(),
        None,
        "policy_path_excluded".to_string(),
    ));
    assert_eq!(memory_filtered, disk_filtered);
    assert!(disk_filtered.contains(&(
        "apps/legacy".to_string(),
        None,
        "policy_path_excluded".to_string()
    )));
    assert!(disk_filtered.contains(&(
        "services/api".to_string(),
        Some("pkg:cargo/serde@1.0.190".to_string()),
        "policy_package_ignored".to_string()
    )));
}

#[tokio::test]
async fn parity_socket_yml_severity_floor() {
    let (patches, repo) = policy_repo("version: 2\npatches:\n  minSeverity: critical\n");
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let memory = run_engine(&server, policy_input(&repo)).await;
    let web = memory
        .projects
        .iter()
        .find(|p| p.root == "apps/web")
        .unwrap();
    assert!(web.redirected.is_empty(), "{:#}", web.redirect);
    assert!(
        web.skipped.iter().any(|s| s.reason == "policy_severity"),
        "{:?}",
        web.skipped
    );
    assert!(engine_changed(&memory).is_empty());
    let disk = run_disk_in(&server, &repo, "apps/web", false);
    assert!(disk.changed.is_empty());
    assert_eq!(disk.redirect, sorted_redirect(&web.redirect));
    let memory_web: std::collections::BTreeSet<_> = filtered_set(memory.policy.as_ref().unwrap())
        .into_iter()
        .filter(|(project, _, _)| project == "apps/web")
        .collect();
    assert_eq!(memory_web, filtered_set(&disk.envelope["policy"]));
}

#[tokio::test]
async fn memory_policy_file_withheld_or_invalid_is_a_policy_error() {
    let (patches, repo) = policy_repo("version: 2\npatches:\n  maxNewPatches: 1\n");
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let opts = policy_options(&repo);
    // Listed by selection but never streamed.
    let mut withheld = repo.clone();
    withheld.remove("socket.yml");
    let out = run_engine(&server, build_input(&withheld, &[], opts.clone())).await;
    let err = out.policy_error.expect("policyError");
    assert_eq!(err.code, "socket_yml_invalid");
    assert!(out.projects.is_empty() && out.changed_files.is_empty() && out.policy.is_none());
    // Streamed present-without-content.
    let out = run_engine(
        &server,
        build_input(&withheld, &["socket.yml"], opts.clone()),
    )
    .await;
    assert_eq!(
        out.policy_error.expect("policyError").code,
        "socket_yml_invalid"
    );
    // Content other than what selection read.
    let mut changed = repo.clone();
    changed.insert("socket.yml".to_string(), b"version: 2\n".to_vec());
    let out = run_engine(&server, build_input(&changed, &[], opts.clone())).await;
    let err = out.policy_error.expect("policyError");
    assert!(err.detail.contains("differs"), "{}", err.detail);
    // The file streamed without selection's policySha256.
    let mut no_sha = opts.clone();
    no_sha.policy_sha256 = None;
    let out = run_engine(&server, build_input(&repo, &[], no_sha)).await;
    assert_eq!(
        out.policy_error.expect("policyError").code,
        "socket_yml_invalid"
    );
    // Invalid content: selection refuses it before anything is fetched.
    let (_, bad) = policy_repo("version: 2\npatches:\n  apiUrl: https://evil.example\n");
    let (selection, _) = two_phase(&bad, options(false));
    let err = selection.policy_error.expect("selection policyError");
    assert!(err.detail.contains("patches.apiUrl"), "{}", err.detail);
    assert!(selection.roots.is_empty() && selection.fetch_text.is_empty());
    let out = run_engine(&server, build_input(&bad, &[], opts.clone())).await;
    let err = out.policy_error.expect("policyError");
    assert!(err.detail.contains("patches.apiUrl"), "{}", err.detail);
    assert!(out.changed_files.is_empty());
    // A bypassed session with a selection that applied the file.
    let mut half = opts.clone();
    half.no_socket_yml = Some(true);
    let out = run_engine(&server, build_input(&repo, &[], half)).await;
    assert_eq!(
        out.policy_error.expect("policyError").code,
        "socket_yml_invalid"
    );
    // noSocketYml skips it on both sides.
    let mut bypass = options(false);
    bypass.no_socket_yml = Some(true);
    let (selection, input) = two_phase(&bad, bypass);
    assert!(selection.policy_error.is_none() && selection.policy_sha256.is_none());
    let out = run_engine(&server, input).await;
    assert!(out.policy_error.is_none());
    assert_eq!(out.policy.unwrap()["source"], "bypassed");
}

#[tokio::test]
async fn memory_min_severity_option_beats_the_file() {
    let (patches, repo) = policy_repo("version: 2\npatches:\n  minSeverity: critical\n");
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let mut opts = options(false);
    opts.min_severity = Some("none".to_string());
    let (_, input) = two_phase(&repo, opts);
    let out = run_engine(&server, input).await;
    let policy = out.policy.unwrap();
    assert_eq!(
        policy["minSeverity"],
        serde_json::json!({"value": null, "source": "flag"})
    );
    assert!(out.projects.iter().any(|p| !p.redirected.is_empty()));
    let mut bad = options(false);
    bad.min_severity = Some("severe".to_string());
    assert!(socket_patch_cli::hosted_memory::SessionBuilder::new(bad).is_err());
}

#[test]
fn selection_applies_the_path_policy_and_fails_closed() {
    use socket_patch_cli::hosted_memory::{
        select_paths, PolicyFileInput, SelectOptions, TreeEntryInput,
    };
    let blob = |path: &str, mode: &str| TreeEntryInput {
        path: path.to_string(),
        mode: mode.to_string(),
        kind: "blob".into(),
        size: Some(1),
    };
    let text = |path: &str, text: &str| PolicyFileInput {
        path: path.to_string(),
        text: Some(text.to_string()),
        missing: None,
    };
    let mut entries = vec![
        blob("socket.yml", "100644"),
        blob("Socket.yml", "100644"),
        blob("apps/web/package-lock.json", "100644"),
        blob("apps/web/tests/app/package-lock.json", "100644"),
        blob("Fixtures/x/yarn.lock", "100644"),
        blob("apps/old/yarn.lock", "100644"),
    ];
    let with = |files: Vec<PolicyFileInput>| SelectOptions {
        policy_files: Some(files),
        ..SelectOptions::default()
    };
    let yml = "version: 2\npatches:\n  ignorePaths: [\"/apps/old/\"]\n";
    let selection = select_paths(&entries, &with(vec![text("socket.yml", yml)]));
    assert!(
        selection.policy_error.is_none(),
        "{:?}",
        selection.policy_error
    );
    assert_eq!(selection.policy_paths, vec!["socket.yml"]);
    assert_eq!(selection.policy_sha256.as_ref().map(String::len), Some(64));
    assert!(selection.fetch_text.contains(&"socket.yml".to_string()));
    assert_eq!(selection.roots, vec!["apps/web"]);
    // Excluded roots (file list and built-in ignores, any case) are
    // reported and never streamed.
    for path in [
        "apps/old/yarn.lock",
        "apps/web/tests/app/package-lock.json",
        "Fixtures/x/yarn.lock",
    ] {
        assert!(
            selection
                .ignored_sample
                .iter()
                .any(|i| i.path == path && i.reason == "policy_path_excluded"),
            "{path}: {selection:?}"
        );
        assert!(
            !selection.fetch_text.contains(&path.to_string())
                && !selection.present_only.contains(&path.to_string()),
            "{path}"
        );
    }
    // Named roots are explicit: the built-in ignores do not apply.
    let named = select_paths(
        &entries,
        &SelectOptions {
            project_roots: Some(vec!["apps/web/tests/app".to_string()]),
            ..with(vec![text("socket.yml", yml)])
        },
    );
    assert_eq!(named.roots, vec!["apps/web/tests/app"]);
    // A listed policy file with no text, `missing`, or invalid text fails
    // closed: nothing is selected.
    let missing = PolicyFileInput {
        path: "socket.yml".to_string(),
        text: None,
        missing: Some(true),
    };
    for files in [
        vec![],
        vec![missing],
        vec![text("socket.yml", "version: 2\npatches:\n  apiUrl: x\n")],
    ] {
        let out = select_paths(&entries, &with(files));
        assert_eq!(
            out.policy_error.as_ref().map(|e| e.code.as_str()),
            Some("socket_yml_invalid")
        );
        assert!(out.roots.is_empty() && out.fetch_text.is_empty(), "{out:?}");
        assert_eq!(out.policy_paths, vec!["socket.yml"]);
    }
    let out = select_paths(&entries, &with(vec![text("nested/socket.yml", yml)]));
    assert!(out.policy_error.is_some());
    // A symlinked policy file is never read.
    entries.push(blob("socket.yaml", "120000"));
    let out = select_paths(
        &entries,
        &with(vec![text("socket.yml", yml), text("socket.yaml", yml)]),
    );
    assert_eq!(
        out.policy_error.map(|e| e.code),
        Some("socket_yml_invalid".to_string())
    );
    // noSocketYml: only the built-in ignores; the file need not be passed.
    let out = select_paths(
        &entries,
        &SelectOptions {
            no_socket_yml: Some(true),
            ..SelectOptions::default()
        },
    );
    assert!(out.policy_error.is_none() && out.policy_sha256.is_none());
    assert_eq!(out.roots, vec!["apps/old", "apps/web"]);
}

#[tokio::test]
async fn memory_negation_reincludes_a_default_ignored_root() {
    let npm = fixtures_root().join("redirect/npm/package-lock-v3/basic");
    let patches = patches_from_overrides(&npm.join("overrides.json"), None);
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let mut repo: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for root in ["e2e/tests", "x/tests"] {
        for (rel, bytes) in fixture_files(&npm.join("input")) {
            repo.insert(format!("{root}/{rel}"), bytes);
        }
    }
    repo.insert(
        "socket.yml".to_string(),
        b"version: 2\npatches:\n  ignorePaths: [\"!/e2e/tests/\"]\n".to_vec(),
    );
    let (selection, input) = two_phase(&repo, options(false));
    assert_eq!(selection.roots, vec!["e2e/tests"]);
    assert!(selection
        .fetch_text
        .contains(&"e2e/tests/package-lock.json".to_string()));
    assert!(
        !selection.fetch_text.iter().any(|p| p.starts_with("x/")),
        "{selection:?}"
    );
    assert!(selection
        .ignored_sample
        .iter()
        .any(|i| i.path == "x/tests/package-lock.json" && i.reason == "policy_path_excluded"));
    let memory = run_engine(&server, input).await;
    let roots: Vec<&str> = memory.projects.iter().map(|p| p.root.as_str()).collect();
    assert_eq!(roots, vec!["e2e/tests"]);
    assert!(
        !memory.projects[0].redirected.is_empty(),
        "{:#}",
        memory.projects[0].redirect
    );

    // Given every root anyway, the session applies the same filter itself.
    let direct = run_engine(&server, build_input(&repo, &[], policy_options(&repo))).await;
    let roots: Vec<&str> = direct.projects.iter().map(|p| p.root.as_str()).collect();
    assert_eq!(roots, vec!["e2e/tests"]);
    let entry = &direct.policy.as_ref().unwrap()["filtered"][0];
    assert_eq!(
        (entry["project"].as_str(), entry["detail"].as_str()),
        (Some("x/tests"), Some("tests/ (built-in default)"))
    );

    // Disk patches the same root the same way.
    let disk = run_disk_in(&server, &repo, "e2e/tests", false);
    assert_eq!(disk.envelope["status"], "success", "{}", disk.stderr);
    assert_eq!(sorted_redirect(&memory.projects[0].redirect), disk.redirect);
    let memory_changed = engine_changed(&memory);
    assert_eq!(
        memory_changed,
        disk.changed,
        "{}",
        describe(&memory_changed)
    );
}

/// A pnpm workspace (#492): the root `pnpm-workspace.yaml` (`ws`), a root
/// `package.json`, the root lock when given, `extra` files, and each
/// `members` directory with a manifest and the golden pnpm fixture's lock
/// (left-pad as a direct dependency).
fn pnpm_workspace(
    ws: &str,
    root_lock: Option<&str>,
    members: &[&str],
    extra: &[(&str, &str)],
) -> BTreeMap<String, Vec<u8>> {
    let lock = read_fixture("redirect/npm/pnpm/basic/input/pnpm-lock.yaml");
    let mut files = BTreeMap::from([
        ("pnpm-workspace.yaml".to_string(), ws.as_bytes().to_vec()),
        (
            "package.json".to_string(),
            br#"{ "name": "root", "private": true }"#.to_vec(),
        ),
    ]);
    if let Some(text) = root_lock {
        files.insert("pnpm-lock.yaml".into(), text.as_bytes().to_vec());
    }
    for member in members {
        files.insert(
            format!("{member}/package.json"),
            format!(r#"{{ "name": "{member}", "dependencies": {{ "left-pad": "1.3.0" }} }}"#)
                .into_bytes(),
        );
        files.insert(format!("{member}/pnpm-lock.yaml"), lock.clone());
    }
    for (rel, text) in extra {
        files.insert(rel.to_string(), text.as_bytes().to_vec());
    }
    files
}

/// The root lock of a workspace whose members have no lock of their own.
const PNPM_ROOT_ONLY_LOCK: &str = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n";

/// The in-memory run over `files` (straight, and through path selection)
/// against the disk run from the repo root: both memory runs have the
/// project `roots` (a member keeps a root of its own only with another
/// lock), none fails, the root project's `redirect` block and every changed
/// byte match the disk run, and no other project redirects anything.
/// Returns the disk run's `redirect` block and changed files.
async fn assert_pnpm_workspace_parity(
    files: &BTreeMap<String, Vec<u8>>,
    trust_lockfile_config: bool,
) -> (Value, BTreeMap<String, Vec<u8>>) {
    assert_pnpm_workspace_parity_with_roots(files, trust_lockfile_config, &[""]).await
}

async fn assert_pnpm_workspace_parity_with_roots(
    files: &BTreeMap<String, Vec<u8>>,
    trust_lockfile_config: bool,
    roots: &[&str],
) -> (Value, BTreeMap<String, Vec<u8>>) {
    assert_pnpm_workspace_parity_granted(files, trust_lockfile_config, roots, false).await
}

/// [`assert_pnpm_workspace_parity_with_roots`]. With `registry`, the patch
/// service also offers each patch's own registry: the directory its
/// tarball is served from, which hosted mode can route a pnpm lock through.
async fn assert_pnpm_workspace_parity_granted(
    files: &BTreeMap<String, Vec<u8>>,
    trust_lockfile_config: bool,
    roots: &[&str],
    registry: bool,
) -> (Value, BTreeMap<String, Vec<u8>>) {
    let dir = fixtures_root().join("redirect/npm/pnpm/basic");
    let server = MockServer::start().await;
    let mut patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    for patch in patches.iter_mut().filter(|_| registry) {
        let url = patch.reference["url"]
            .as_str()
            .expect("a tarball")
            .to_string();
        let directory = &url[..=url.rfind('/').expect("the URL of a tarball")];
        patch.reference["npmRegistryUrl"] = directory.into();
    }
    mount_api(&server, &patches).await;
    let extra: &[&str] = if trust_lockfile_config {
        &[]
    } else {
        &["--no-trust-lockfile-config"]
    };
    let disk = run_disk_with(&server, files, false, extra);
    let mut opts = options(false);
    opts.trust_lockfile_config = Some(trust_lockfile_config);
    let straight = run_engine(&server, build_input(files, &[], opts)).await;
    let mut selected = selected_input(files);
    selected.options.trust_lockfile_config = Some(trust_lockfile_config);
    let through_selection = run_engine(&server, selected).await;
    for (how, memory) in [("straight", &straight), ("selection", &through_selection)] {
        let found: Vec<&str> = memory.projects.iter().map(|p| p.root.as_str()).collect();
        assert_eq!(
            found, roots,
            "{how}: member locks belong to the workspace root"
        );
        for project in &memory.projects {
            assert!(
                project.error.is_none(),
                "{how}: {}: {:?}",
                project.root,
                project.error
            );
        }
        let project = memory
            .projects
            .iter()
            .find(|p| p.root.is_empty())
            .unwrap_or_else(|| panic!("{how}: no workspace root project"));
        assert!(project.error.is_none(), "{how}: {:?}", project.error);
        assert_eq!(
            sorted_redirect(&project.redirect),
            disk.redirect,
            "{how}: redirect block differs\nstderr: {}",
            disk.stderr
        );
        for other in memory.projects.iter().filter(|p| !p.root.is_empty()) {
            assert!(other.redirected.is_empty(), "{how}: {}", other.root);
        }
        let changed = engine_changed(memory);
        assert_eq!(
            changed,
            disk.changed,
            "{how}\nmemory:\n{}\ndisk:\n{}",
            describe(&changed),
            describe(&disk.changed)
        );
    }
    (disk.redirect.clone(), disk.changed)
}

/// #492: under `sharedWorkspaceLockfile: false` (or pnpm 7's `.npmrc`
/// spelling with no root lock at all) both engines pin every member's own
/// lock from the workspace root and trust them in the root file.
#[tokio::test]
async fn parity_pnpm_member_locks_are_pinned_from_the_workspace_root() {
    let members = ["packages/a", "packages/b"];
    for files in [
        pnpm_workspace(
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
            Some(PNPM_ROOT_ONLY_LOCK),
            &members,
            &[],
        ),
        pnpm_workspace(
            "packages:\n  - 'packages/*'\n",
            None,
            &members,
            &[(".npmrc", "shared-workspace-lockfile=false\n")],
        ),
    ] {
        let (redirect, changed) = assert_pnpm_workspace_parity(&files, true).await;
        assert_eq!(redirect["redirected"], 1, "{redirect:#}");
        let paths: Vec<&str> = changed.keys().map(String::as_str).collect();
        assert_eq!(
            paths,
            [
                "packages/a/pnpm-lock.yaml",
                "packages/b/pnpm-lock.yaml",
                "pnpm-workspace.yaml"
            ]
        );
        assert!(String::from_utf8_lossy(&changed["pnpm-workspace.yaml"])
            .ends_with("trustLockfile: true\n"));
    }
}

/// #492: the trust auto-config over member locks is the same in both
/// engines: an explicit root-file value is respected, an existing `true`
/// is kept, and with the auto-config off nothing but the locks is written.
#[tokio::test]
async fn parity_pnpm_member_lock_trust_config() {
    let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
    for (trust_line, auto_config) in [
        ("trustLockfile: false\n", true),
        ("trustLockfile: true\n", true),
        ("", false),
    ] {
        let files = pnpm_workspace(
            &format!("{ws}{trust_line}"),
            Some(PNPM_ROOT_ONLY_LOCK),
            &["packages/a"],
            &[],
        );
        let (redirect, changed) = assert_pnpm_workspace_parity(&files, auto_config).await;
        let paths: Vec<&str> = changed.keys().map(String::as_str).collect();
        assert_eq!(paths, ["packages/a/pnpm-lock.yaml"], "{trust_line:?}");
        let codes = redirect["warnings"].to_string();
        assert!(codes.contains("redirect_pnpm_trust_lockfile"), "{codes}");
    }
}

/// #492 + #556: a member's branch lock under `gitBranchLockfile` refuses
/// every pnpm pin in both engines, nothing written.
#[tokio::test]
async fn parity_pnpm_member_branch_lock_refusal() {
    let files = pnpm_workspace(
        "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\ngitBranchLockfile: true\n",
        Some(PNPM_ROOT_ONLY_LOCK),
        &["packages/a"],
        &[(
            "packages/a/pnpm-lock.feature.yaml",
            "lockfileVersion: '9.0'\n",
        )],
    );
    let (redirect, changed) = assert_pnpm_workspace_parity(&files, true).await;
    assert!(changed.is_empty(), "{}", describe(&changed));
    assert!(
        redirect["warnings"]
            .to_string()
            .contains("redirect_pnpm_git_branch_lockfile"),
        "{redirect:#}"
    );
}

/// A rules_js hub of the project's `MODULE.bazel` that keeps the pnpm lock
/// up to date with pnpm 11 and does not list `pnpm-workspace.yaml` as
/// `data`: the pnpm that Bazel runs would reject a pinned lock, so both
/// engines refuse every pnpm pin with the same warning, nothing written.
/// Path selection asks for the `MODULE.bazel` beside the lock. With a
/// file of the user's own listed both engines pin the lock; with a listed
/// file that the undo of the pin would remove both pin nothing. The engine
/// judges the hub unless `SOCKET_NO_BAZEL` is set, so the test holds the
/// variable unset.
#[tokio::test]
#[serial_test::serial]
async fn parity_pnpm_bazel_hub_that_hides_the_workspace_file() {
    let _unset = EnvGuard::unset("SOCKET_NO_BAZEL");
    let lock =
        String::from_utf8(read_fixture("redirect/npm/pnpm/basic/input/pnpm-lock.yaml")).unwrap();
    let module = |data: &str| {
        format!(
            "module(name = \"app\")\n\
             bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
             npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
             npm.npm_translate_lock(\n    name = \"npm\",\n{data}    \
             pnpm_lock = \"//:pnpm-lock.yaml\",\n    update_pnpm_lock = True,\n)\n\
             pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
             pnpm.pnpm(name = \"pnpm\", pnpm_version = \"11.28.10\")\n"
        )
    };
    let workspace = "# own\npackages:\n  - '.'\n";
    let hidden = module("");
    let files = pnpm_workspace(workspace, Some(&lock), &[], &[("MODULE.bazel", &hidden)]);
    let (redirect, changed) = assert_pnpm_workspace_parity(&files, true).await;
    assert!(changed.is_empty(), "{}", describe(&changed));
    let warned = redirect["warnings"].to_string();
    let code = "redirect_pnpm_bazel_workspace_hidden";
    assert!(warned.contains(code), "{redirect:#}");
    assert!(warned.contains("MODULE.bazel:4: "), "{redirect:#}");

    let listed = module("    data = [\"//:pnpm-workspace.yaml\"],\n");
    let files = pnpm_workspace(workspace, Some(&lock), &[], &[("MODULE.bazel", &listed)]);
    let (redirect, changed) = assert_pnpm_workspace_parity(&files, true).await;
    let paths: Vec<&str> = changed.keys().map(String::as_str).collect();
    assert_eq!(paths, ["pnpm-lock.yaml", "pnpm-workspace.yaml"]);
    assert!(
        !redirect["warnings"].to_string().contains(code),
        "{redirect:#}"
    );

    // Listed, but a file that the undo of the pin would remove: both
    // engines pin nothing, so that no `rollback` leaves the call with a
    // missing file.
    let scaffold = "packages:\n  - '.'\n";
    let files = pnpm_workspace(scaffold, Some(&lock), &[], &[("MODULE.bazel", &listed)]);
    let (redirect, changed) = assert_pnpm_workspace_parity(&files, true).await;
    assert!(changed.is_empty(), "{}", describe(&changed));
    let warned = redirect["warnings"].to_string();
    assert!(warned.contains(code), "{redirect:#}");
    assert!(
        warned.contains("put a comment line in pnpm-workspace.yaml"),
        "{redirect:#}"
    );
}

/// A rules_js hub that reads the pnpm lock, a patch whose registry the
/// patch service offers and a project that proves pnpm 12: both engines
/// give the one answer. A hub that runs no pnpm, and one whose pnpm 11
/// reads the user's `pnpm-workspace.yaml`, have the lock routed through
/// the registry. The same hub with a pnpm 10 keeps the pin with
/// `trustLockfile: true`, and the warning says what kept it off the
/// route. Told not to write to the workspace file, both engines write
/// nothing beside the hub whose pnpm 11 would reject the pin, and say what
/// to do.
#[tokio::test]
async fn parity_pnpm_bazel_hub_and_the_registry_route() {
    let lock =
        String::from_utf8(read_fixture("redirect/npm/pnpm/basic/input/pnpm-lock.yaml")).unwrap();
    let module = |hub: &str, pnpm: &str| {
        format!(
            "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
             npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
             npm.npm_translate_lock(pnpm_lock = \"//:pnpm-lock.yaml\"{hub})\n\
             pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
             pnpm.pnpm(name = \"pnpm\", pnpm_version = \"{pnpm}\")\n"
        )
    };
    let listing = ", update_pnpm_lock = True, data = [\"//:pnpm-workspace.yaml\"]";
    let manifest = r#"{ "name": "root", "private": true, "packageManager": "pnpm@12.22.0" }"#;
    let run = |module: String, trust: bool| {
        let lock = lock.clone();
        async move {
            let extra = [
                ("MODULE.bazel", module.as_str()),
                ("package.json", manifest),
            ];
            let files = pnpm_workspace("# own\n", Some(&lock), &[], &extra);
            assert_pnpm_workspace_parity_granted(&files, trust, &[""], true).await
        }
    };
    let written = ["pnpm-lock.yaml", "pnpm-workspace.yaml"];
    let workspace = |changed: &BTreeMap<String, Vec<u8>>| {
        String::from_utf8(changed["pnpm-workspace.yaml"].clone()).unwrap()
    };

    for hub in ["", listing] {
        let (redirect, changed) = run(module(hub, "11.28.10"), true).await;
        assert_eq!(changed.keys().collect::<Vec<_>>(), written, "{hub}");
        let workspace = workspace(&changed);
        assert!(
            workspace.contains("namedRegistries:") && !workspace.contains("trustLockfile"),
            "{hub}: {workspace}"
        );
        assert!(
            !redirect["warnings"].to_string().contains("Bazel"),
            "{hub}: {redirect:#}"
        );
    }

    let (redirect, changed) = run(module(listing, "10.34.9"), true).await;
    assert_eq!(changed.keys().collect::<Vec<_>>(), written);
    assert_eq!(
        workspace(&changed),
        "# own\npackages:\n  - '.'\ntrustLockfile: true\n"
    );
    assert!(
        redirect["warnings"].to_string().contains(
            "a Bazel hub reads the pnpm lock (MODULE.bazel:3), and the pnpm it runs for \
             `update_pnpm_lock` is not stated as 11.20 or later (pnpm 10.34.9)"
        ),
        "{redirect:#}"
    );

    let (redirect, changed) = run(module(listing, "11.28.10"), false).await;
    assert!(changed.is_empty(), "{}", describe(&changed));
    let warned = redirect["warnings"].to_string();
    assert!(
        warned.contains("redirect_pnpm_bazel_workspace_hidden")
            && warned.contains(
                "let hosted mode write to pnpm-workspace.yaml (this run was told not to, which \
                 is `--no-trust-lockfile-config` on the command line"
            ),
        "{redirect:#}"
    );
}

/// #492: a member lock beside a shared root lock (one listing the member's
/// importer) is a stale leftover pnpm never reads: both engines pin the
/// root lock alone.
#[tokio::test]
async fn parity_pnpm_stale_member_lock_under_a_shared_lock() {
    let lock =
        String::from_utf8(read_fixture("redirect/npm/pnpm/basic/input/pnpm-lock.yaml")).unwrap();
    let shared = lock.replacen("  .:\n", "  .: {}\n  packages/a:\n", 1);
    assert_ne!(shared, lock);
    let files = pnpm_workspace(
        "packages:\n  - 'packages/*'\n",
        Some(&shared),
        &["packages/a"],
        &[],
    );
    let (redirect, changed) = assert_pnpm_workspace_parity(&files, true).await;
    assert_eq!(redirect["redirected"], 1, "{redirect:#}");
    let paths: Vec<&str> = changed.keys().map(String::as_str).collect();
    assert_eq!(paths, ["pnpm-lock.yaml", "pnpm-workspace.yaml"]);
}

/// The two in-memory runs of `files`: straight, and through path selection
/// (its `roots` passed back as `projectRoots`), both with `opts`.
async fn pnpm_memory_runs(
    server: &MockServer,
    files: &BTreeMap<String, Vec<u8>>,
    opts: &socket_patch_cli::hosted_memory::HostedScanOptions,
) -> [(
    &'static str,
    socket_patch_cli::hosted_memory::HostedScanOutput,
); 2] {
    let straight = run_engine(server, build_input(files, &[], opts.clone())).await;
    let mut selected = selected_input(files);
    let roots = selected.options.project_roots.take();
    selected.options = socket_patch_cli::hosted_memory::HostedScanOptions {
        project_roots: roots,
        ..opts.clone()
    };
    let through_selection = run_engine(server, selected).await;
    [("straight", straight), ("selection", through_selection)]
}

fn project_roots(output: &socket_patch_cli::hosted_memory::HostedScanOutput) -> Vec<&str> {
    output.projects.iter().map(|p| p.root.as_str()).collect()
}

fn changed_paths(output: &socket_patch_cli::hosted_memory::HostedScanOutput) -> Vec<&str> {
    output
        .changed_files
        .iter()
        .map(|f| f.path.as_str())
        .collect()
}

async fn pnpm_server() -> MockServer {
    let dir = fixtures_root().join("redirect/npm/pnpm/basic");
    let server = MockServer::start().await;
    mount_api(
        &server,
        &patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri())),
    )
    .await;
    server
}

/// #492: a member holding another lock (npm, yarn, Cargo) stays a root of
/// its own for that lock, while its pnpm lock is pinned from the workspace
/// root, as on disk; only the workspace root's project redirects.
#[tokio::test]
async fn parity_pnpm_member_with_another_lock_keeps_its_root() {
    let files = pnpm_workspace(
        "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        Some(PNPM_ROOT_ONLY_LOCK),
        &["packages/a", "packages/b"],
        &[(
            "packages/a/package-lock.json",
            r#"{ "name": "a", "lockfileVersion": 3, "requires": true, "packages": { "": { "name": "a" } } }"#,
        )],
    );
    let (_, changed) =
        assert_pnpm_workspace_parity_with_roots(&files, true, &["", "packages/a"]).await;
    let paths: Vec<&str> = changed.keys().map(String::as_str).collect();
    assert_eq!(
        paths,
        [
            "packages/a/pnpm-lock.yaml",
            "packages/b/pnpm-lock.yaml",
            "pnpm-workspace.yaml"
        ]
    );
}

/// #492: a member lock whose workspace root cannot be confirmed to read it
/// (an unreadable root file, a glob the matcher does not model, no package
/// manifest beside the lock, or a shared workspace with no root lock to
/// install from) is never silently dropped: it stays a root of its own,
/// pinned with the trust auto-config off and refused with it on, as before.
#[tokio::test]
async fn an_unconfirmed_pnpm_member_keeps_its_lock() {
    let server = pnpm_server().await;
    let per_member = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
    let unmodeled = pnpm_workspace(
        // Brace sets and classes are read (#1846); an extglob is not.
        "packages:\n  - 'packages/@(a|b)'\nsharedWorkspaceLockfile: false\n",
        Some(PNPM_ROOT_ONLY_LOCK),
        &["packages/a"],
        &[],
    );
    let mut no_manifest =
        pnpm_workspace(per_member, Some(PNPM_ROOT_ONLY_LOCK), &["packages/a"], &[]);
    no_manifest.remove("packages/a/package.json");
    let shared_no_root_lock =
        pnpm_workspace("packages:\n  - 'packages/*'\n", None, &["packages/a"], &[]);
    let readable = pnpm_workspace(per_member, Some(PNPM_ROOT_ONLY_LOCK), &["packages/a"], &[]);
    // (name, files, paths passed presence-only, expected roots)
    type Case<'a> = (
        &'a str,
        &'a BTreeMap<String, Vec<u8>>,
        &'a [&'a str],
        &'a [&'a str],
    );
    let cases: [Case; 4] = [
        ("unmodeled glob", &unmodeled, &[], &["", "packages/a"]),
        ("no manifest", &no_manifest, &[], &["", "packages/a"]),
        (
            "shared, no root lock",
            &shared_no_root_lock,
            &[],
            &["packages/a"],
        ),
        (
            "unreadable root file",
            &readable,
            &["pnpm-workspace.yaml"],
            &["", "packages/a"],
        ),
    ];
    for (name, files, present, roots) in cases {
        let mut files = files.clone();
        for path in present {
            files.remove(*path);
        }
        for trust in [true, false] {
            let mut opts = options(false);
            opts.trust_lockfile_config = Some(trust);
            let output = run_engine(&server, build_input(&files, present, opts)).await;
            assert_eq!(project_roots(&output), roots, "{name}");
            let member = output
                .projects
                .iter()
                .find(|p| p.root == "packages/a")
                .unwrap();
            let paths = changed_paths(&output);
            if trust {
                let error = member
                    .error
                    .as_ref()
                    .unwrap_or_else(|| panic!("{name}: not refused"));
                assert_eq!(
                    error.code, "redirect_pnpm_settings_elsewhere",
                    "{name}: {error:?}"
                );
                assert!(
                    !paths.iter().any(|p| p.starts_with("packages/a/")),
                    "{name}: {paths:?}"
                );
            } else {
                assert!(member.error.is_none(), "{name}: {:?}", member.error);
                assert!(
                    paths.contains(&"packages/a/pnpm-lock.yaml"),
                    "{name}: {paths:?}"
                );
            }
            assert!(
                !output
                    .warnings
                    .iter()
                    .any(|w| w.code == "pnpm_member_lock_ignored"),
                "{name}: {:?}",
                output.warnings
            );
        }
    }
}

/// #492 with `--ecosystems`: a workspace root is added only for npm. A
/// member detected for its Cargo.lock under a cargo-only filter keeps its
/// root and no lockless workspace root joins it, straight or through
/// selection.
#[tokio::test]
async fn pnpm_workspace_roots_follow_the_ecosystem_filter() {
    use socket_patch_cli::hosted_memory::{select_paths, SelectOptions, TreeEntryInput};
    let server = pnpm_server().await;
    let files = pnpm_workspace(
        "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        None,
        &["packages/a"],
        &[("packages/a/Cargo.lock", "version = 3\n")],
    );
    let entries: Vec<TreeEntryInput> = files
        .keys()
        .map(|p| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: None,
        })
        .collect();
    let cargo = Some(vec!["cargo".to_string()]);
    let selection = select_paths(
        &entries,
        &SelectOptions {
            ecosystems: cargo.clone(),
            ..SelectOptions::default()
        },
    );
    assert_eq!(selection.roots, ["packages/a"]);
    let mut opts = options(false);
    opts.ecosystems = cargo;
    let output = run_engine(&server, build_input(&files, &[], opts)).await;
    assert_eq!(project_roots(&output), ["packages/a"]);
}

/// #492 with socket.yml: a member lock is demoted only into a workspace
/// root the path policy admits. With `includePaths` leaving the root out,
/// each member stays a root of its own and is pinned, through the host's
/// two-phase flow and straight alike.
#[tokio::test]
async fn a_pnpm_member_stays_a_root_when_socket_yml_leaves_the_workspace_root_out() {
    let server = pnpm_server().await;
    let mut files = pnpm_workspace(
        "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        Some(PNPM_ROOT_ONLY_LOCK),
        &["packages/a", "packages/b"],
        &[],
    );
    files.insert(
        "socket.yml".into(),
        b"version: 2\npatches:\n  includePaths: [\"packages/**\"]\n".to_vec(),
    );
    let mut opts = options(false);
    opts.trust_lockfile_config = Some(false);
    let (_, two_phase_input) = two_phase(&files, opts.clone());
    let mut direct_opts = policy_options(&files);
    direct_opts.trust_lockfile_config = Some(false);
    for (how, input) in [
        ("two-phase", two_phase_input),
        ("direct", build_input(&files, &[], direct_opts)),
    ] {
        let output = run_engine(&server, input).await;
        assert_eq!(
            project_roots(&output),
            ["packages/a", "packages/b"],
            "{how}"
        );
        assert_eq!(
            changed_paths(&output),
            ["packages/a/pnpm-lock.yaml", "packages/b/pnpm-lock.yaml"],
            "{how}"
        );
    }
}

/// #492 with nested workspaces: a member belongs to the nearest
/// `pnpm-workspace.yaml` (pnpm looks no further), so its lock is demoted
/// into the inner workspace root, which the outer one lists as a member
/// with its own file and so stays a root. Straight and through selection
/// give the same roots and writes, with no conflicting write.
#[tokio::test]
async fn nested_pnpm_workspaces_demote_into_the_nearest_root() {
    let server = pnpm_server().await;
    let per_member =
        |globs: &str| format!("packages:\n  - '{globs}'\nsharedWorkspaceLockfile: false\n");
    let lock =
        String::from_utf8(read_fixture("redirect/npm/pnpm/basic/input/pnpm-lock.yaml")).unwrap();
    let inner_ws = per_member("m/*");
    let files = pnpm_workspace(
        &per_member("packages/*"),
        Some(PNPM_ROOT_ONLY_LOCK),
        &["packages/x/m/a"],
        &[
            ("packages/x/pnpm-workspace.yaml", inner_ws.as_str()),
            ("packages/x/package.json", r#"{ "name": "x" }"#),
            ("packages/x/pnpm-lock.yaml", lock.as_str()),
        ],
    );
    let runs = pnpm_memory_runs(&server, &files, &options(false)).await;
    for (how, output) in &runs {
        assert_eq!(project_roots(output), ["", "packages/x"], "{how}");
        for project in &output.projects {
            assert!(
                project.error.is_none(),
                "{how}: {}: {:?}",
                project.root,
                project.error
            );
        }
        let paths = changed_paths(output);
        for path in ["packages/x/m/a/pnpm-lock.yaml", "packages/x/pnpm-lock.yaml"] {
            assert!(paths.contains(&path), "{how}: {paths:?}");
        }
        assert!(
            !output
                .warnings
                .iter()
                .any(|w| w.code == "conflicting_write"),
            "{how}: {:?}",
            output.warnings
        );
    }
    assert_eq!(engine_changed(&runs[0].1), engine_changed(&runs[1].1));
}

/// #492 through selection: a lockless directory selection adds only
/// because a `pnpm-workspace.yaml` sits above a pnpm root, which that file
/// does not list, is no project; the root keeps its lock.
#[tokio::test]
async fn a_pnpm_workspace_file_listing_nothing_adds_no_root() {
    let server = pnpm_server().await;
    let lock =
        String::from_utf8(read_fixture("redirect/npm/pnpm/basic/input/pnpm-lock.yaml")).unwrap();
    let files: BTreeMap<String, Vec<u8>> = [
        ("examples/pnpm-workspace.yaml", "packages: []\n"),
        ("examples/demo/package.json", r#"{ "name": "demo" }"#),
        ("examples/demo/pnpm-lock.yaml", lock.as_str()),
    ]
    .into_iter()
    .map(|(p, t)| (p.to_string(), t.as_bytes().to_vec()))
    .collect();
    for (how, output) in pnpm_memory_runs(&server, &files, &options(false)).await {
        assert_eq!(project_roots(&output), ["examples/demo"], "{how}");
        assert!(
            changed_paths(&output).contains(&"examples/demo/pnpm-lock.yaml"),
            "{how}: {:?}",
            output.changed_files
        );
    }
}

/// The in-memory engine through path selection, and the disk flow, over a
/// project whose `left-pad@1.3.0` (the pnpm golden fixture's patch) the
/// project may patch itself: the `redirected` count of each, and whether
/// the memory root project skipped a candidate `user_patch_conflict`.
/// The memory run is made twice through selection: with the roots it
/// detects, and with the caller naming the root (`projectRoots: [""]`),
/// where a pnpm member with a lock is no root of its own; both must agree.
async fn user_patch_runs(files: &BTreeMap<String, Vec<u8>>) -> (u64, usize, bool) {
    use socket_patch_cli::hosted_memory::{select_paths, SelectOptions, TreeEntryInput};
    let dir = fixtures_root().join("redirect/npm/pnpm/basic");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let disk = run_disk_with(&server, files, false, &["--no-trust-lockfile-config"]);
    let entries: Vec<TreeEntryInput> = files
        .iter()
        .map(|(p, bytes)| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(bytes.len() as u64),
        })
        .collect();
    let mut runs = Vec::new();
    for roots in [None, Some(vec![String::new()])] {
        let selection = select_paths(
            &entries,
            &SelectOptions {
                project_roots: roots,
                ..SelectOptions::default()
            },
        );
        let fetched: BTreeMap<String, Vec<u8>> = selection
            .fetch_text
            .iter()
            .chain(selection.fetch_binary.iter())
            .map(|p| (p.clone(), files[p].clone()))
            .collect();
        let present: Vec<&str> = selection.present_only.iter().map(String::as_str).collect();
        let mut opts = options(false);
        opts.project_roots = Some(selection.roots.clone());
        opts.trust_lockfile_config = Some(false);
        let memory = run_engine(&server, build_input(&fetched, &present, opts)).await;
        let root = memory
            .projects
            .iter()
            .find(|p| p.root.is_empty())
            .expect("the root project");
        assert!(root.error.is_none(), "{:?}", root.error);
        let skipped = root
            .skipped
            .iter()
            .any(|s| s.reason == "user_patch_conflict");
        runs.push((root.redirected.len(), skipped));
    }
    assert_eq!(runs[0], runs[1], "detected and named roots agree");
    (
        disk.redirect["redirected"].as_u64().unwrap_or(0),
        runs[0].0,
        runs[0].1,
    )
}

/// Review (#2018): the in-memory engine reads user patches only from the
/// files path selection asks the host for. A pnpm workspace's member
/// manifests, an npm / yarn workspace member's manifest and `patches/`
/// folder, and the root's patch-package files and `--patch-dir` must all
/// be selected (with content where the walk reads it), or the engine
/// either pins a package the project patches itself or withholds every
/// npm package over a file it saw without content. Through selection,
/// memory agrees with the disk flow, whose consent gate reads the same
/// declarations: a patched `left-pad` is never pinned, and an unrelated
/// patch withholds nothing.
#[tokio::test]
async fn user_patches_are_selected_and_agree_with_the_disk_flow() {
    let lock =
        String::from_utf8(read_fixture("redirect/npm/pnpm/basic/input/pnpm-lock.yaml")).unwrap();
    let pnpm_ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
    let member_patch = r#"{ "name": "a", "dependencies": { "left-pad": "1.3.0" }, "pnpm": { "patchedDependencies": { "left-pad@1.3.0": "x.patch" } } }"#;
    let npm_ws = r#"{ "name": "root", "private": true, "workspaces": ["packages/*"] }"#;
    let patch_dir =
        r#"{ "name": "root", "scripts": { "postinstall": "patch-package --patch-dir fixes" } }"#;
    let root_manifest = r#"{ "name": "root", "private": true }"#;
    let with_root_lock = |extra: &[(&str, &str)]| -> Vec<(String, String)> {
        let mut files = vec![("pnpm-lock.yaml".to_string(), lock.clone())];
        files.extend(extra.iter().map(|(p, t)| (p.to_string(), t.to_string())));
        files
    };
    let pnpm_members = |a: &str| -> Vec<(String, String)> {
        vec![
            ("pnpm-workspace.yaml".into(), pnpm_ws.into()),
            ("package.json".into(), root_manifest.into()),
            ("packages/a/package.json".into(), a.into()),
            ("packages/a/pnpm-lock.yaml".into(), lock.clone()),
            (
                "packages/b/package.json".into(),
                r#"{ "name": "b" }"#.into(),
            ),
        ]
    };
    let cases: Vec<(&str, Vec<(String, String)>, bool)> = vec![
        ("pnpm member manifest", pnpm_members(member_patch), true),
        (
            "pnpm members without a patch",
            pnpm_members(r#"{ "name": "a", "dependencies": { "left-pad": "1.3.0" } }"#),
            false,
        ),
        (
            "npm workspace member's patches/",
            with_root_lock(&[
                ("package.json", npm_ws),
                ("packages/a/package.json", r#"{ "name": "a" }"#),
                ("packages/a/patches/left-pad+1.3.0.patch", "diff\n"),
            ]),
            true,
        ),
        (
            "npm workspace member's patch: descriptor",
            with_root_lock(&[
                ("package.json", npm_ws),
                (
                    "packages/a/package.json",
                    r#"{ "name": "a", "resolutions": { "left-pad": "patch:left-pad@npm%3A1.3.0#./p.patch" } }"#,
                ),
            ]),
            true,
        ),
        (
            "npm workspace members without a patch",
            with_root_lock(&[
                ("package.json", npm_ws),
                ("packages/a/package.json", r#"{ "name": "a" }"#),
            ]),
            false,
        ),
        (
            "root patches/",
            with_root_lock(&[("patches/left-pad+1.3.0.patch", "diff\n")]),
            true,
        ),
        (
            "root --patch-dir",
            with_root_lock(&[
                ("package.json", patch_dir),
                ("fixes/left-pad+1.3.0.patch", "diff\n"),
            ]),
            true,
        ),
        (
            "root --patch-dir patching another package",
            with_root_lock(&[
                ("package.json", patch_dir),
                ("fixes/other+1.0.0.patch", "diff\n"),
            ]),
            false,
        ),
    ];
    for (what, files, patched) in cases {
        let files: BTreeMap<String, Vec<u8>> = files
            .into_iter()
            .map(|(p, t)| (p, t.into_bytes()))
            .collect();
        let (disk, memory, skipped) = user_patch_runs(&files).await;
        if patched {
            assert_eq!((disk, memory), (0, 0), "{what}: never pinned");
            assert!(skipped, "{what}: memory skips it user_patch_conflict");
        } else {
            assert!(disk > 0 && memory > 0, "{what}: pinned ({disk}, {memory})");
            assert!(!skipped, "{what}");
        }
    }
}
