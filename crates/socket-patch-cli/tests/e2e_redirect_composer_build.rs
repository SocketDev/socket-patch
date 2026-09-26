//! Real-composer HOSTED (redirect) capstone — the composer twin of
//! `e2e_redirect_npm_build.rs`, ending in the manifest-less VEX legs.
//!
//! `scan --redirect` never lands patched bytes in the repo: it rewrites
//! composer.lock so the patched package's `dist` RESOLVES from Socket's
//! hosted patch archive (here: a wiremock standing in for patch.socket.dev)
//! and pins the archive's sha1 in `dist.shasum`. This proves every link of
//! that chain against the REAL composer (1 or 2 — whatever is on PATH):
//!
//!   1. `composer update` resolves + installs a real psr/log 3.0.x into
//!      `vendor/` (network used for fixture setup only; private home +
//!      cache; composer 1 resolves from an inline package repository — see
//!      `composer_e2e_common`).
//!   2. Build the PATCHED dist zip from the actually-installed package (a
//!      marker comment appended to `src/LoggerInterface.php`, wrapped in a
//!      GitHub-zipball-style top-level dir) and serve it from wiremock with
//!      the discovery / reference / view API mocks.
//!   3. `scan --redirect --json --vex …` (or its `get <uuid> --mode hosted`
//!      twin): composer.lock's psr/log `dist` now points at the wiremock
//!      archive with its sha1, the redirect ledger embeds the record, no
//!      manifest is written, and the in-run VEX is `(redirected)`.
//!   4. FRESH-CHECKOUT PROOF: only composer.json + composer.lock + `.socket/`
//!      travel; a cold-home/cache `composer install` downloads the archive
//!      from the hosted patch server — the installed file is byte-identical
//!      to the patched bytes. (Negative twin: the server serves TAMPERED
//!      bytes under the real sha1 pin → composer's checksum verification
//!      refuses the install — and, because the redirect drops the entry's git
//!      `source`, composer 1 / 2.2 LTS cannot "fall back to source" and
//!      silently install the pristine upstream commit instead.)
//!   5. MANIFEST-LESS VEX on the fresh checkout (the hosted flow never wrote
//!      a manifest; asserted), against a mock patch API:
//!      * ledger kept → standalone `vex` attests `(redirected)` with the
//!        installed tree hash-verified, as does embedded `apply --vex`; a
//!        tampered installed file is `hash_mismatch`;
//!      * ledger deleted → attests from the composer.lock dist (the hosted
//!        origin named by `--patch-server-url`) + the API record; without
//!        that flag a loopback origin is not Socket's and nothing is
//!        discovered;
//!      * `--offline`, no ledger → `record_unavailable`, zero requests;
//!      * composer.lock reverted to the registry dist with the ledger left
//!        behind + a REAL re-install (pristine bytes) → `redirect_unwired`,
//!        `--no-verify` and `--offline` included.
//!
//! Skips (println) when composer is missing or the fixture install cannot
//! reach its registry — unless `SOCKET_PATCH_COMPOSER_E2E_REQUIRED` is set,
//! then those fail. `SOCKET_PATCH_COMPOSER_E2E_VERSION` pins the expected
//! release. `#[ignore]`-gated like the vendored twin: the unpinned `test` job
//! skips it; the e2e job runs it with a pinned toolchain via `--ignored`.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha1::{Digest as _, Sha1};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "composer_e2e_common/mod.rs"]
mod composer_e2e_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use composer_e2e_common::{composer, composer_major, fresh_checkout, setup_psr_log_project};
use vex_e2e_common::{
    assert_absent, assert_attested, assert_not_attested, binary, git_sha256, patch_view, run_vex,
    strip_ledgers, strip_manifest, Marker, PatchApi, VexOutcome, VexRun, VexVia,
};

const SUITE: &str = "e2e_redirect_composer_build";
const ORG: &str = "test-org";
const DEP: &str = "psr/log";
/// Canonical lowercase patch uuid (the LAST uuid segment of the hosted URL).
const UUID: &str = "6c7d8e9f-0a1b-4c2d-8e3f-4a5b6c7d8e9f";
/// Uuid-shaped grant-token segment before it (opaque to the CLI).
const TOKEN: &str = "33333333-3333-4333-8333-333333333333";
const GHSA: &str = "GHSA-hstd-cmps-real";
const CVE: &str = "CVE-2026-55555";
const PRODUCT: &str = "pkg:composer/app@1.0.0";
const FILE_KEY: &str = "src/LoggerInterface.php";

/// Which CLI front door performs the redirect (step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RedirectCli {
    /// `scan --redirect --json --yes --vex …` (embedded VEX asserted).
    ScanRedirectVex,
    /// `get <UUID> --mode hosted --json --yes` (get has no `--vex`).
    GetUuidHosted,
    /// `scan --redirect --yes` in human mode (the next-steps text asserted).
    ScanRedirectHuman,
}

/// The real package a capstone redirects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixturePkg {
    /// psr/log 3.0.x (`composer_e2e_common`'s fixture).
    PsrLog,
    /// symfony/deprecation-contracts `v3.5.1` (PHP ≥ 8.1) or `v2.5.4`: a
    /// release whose lock version carries the `v` tag.
    VTagged,
}

impl FixturePkg {
    fn name(self) -> &'static str {
        match self {
            Self::PsrLog => DEP,
            Self::VTagged => VTAG_DEP,
        }
    }

    fn file_key(self) -> &'static str {
        match self {
            Self::PsrLog => FILE_KEY,
            Self::VTagged => "function.php",
        }
    }

    /// The GitHub-zipball-style top-level dir of the hosted archive.
    fn zip_top(self) -> String {
        match self {
            Self::PsrLog => format!("php-fig-log-{}", &composer_e2e_common::PSR_LOG_REF[..7]),
            Self::VTagged => "symfony-deprecation-contracts-74c71c9".to_string(),
        }
    }

    fn setup(self, suite: &str, proj: &Path, home: &Path, cache: &Path, major: u32) -> Option<()> {
        match self {
            Self::PsrLog => setup_psr_log_project(suite, proj, home, cache, major),
            Self::VTagged => setup_vtag_project(suite, proj, home, cache, major),
        }
    }
}

const VTAG_DEP: &str = "symfony/deprecation-contracts";

/// The v-tagged fixture: Composer picks `v3.5.1` or `v2.5.4` by its PHP;
/// Composer 1 resolves them from an inline package repository.
fn setup_vtag_project(
    suite: &str,
    proj: &Path,
    home: &Path,
    cache: &Path,
    major: u32,
) -> Option<()> {
    let release = |version: &str, reference: &str, php: &str| {
        serde_json::json!({
            "name": VTAG_DEP,
            "version": version,
            "type": "library",
            "dist": {
                "type": "zip",
                "url": format!("https://api.github.com/repos/symfony/deprecation-contracts/zipball/{reference}"),
                "reference": reference,
            },
            "source": {
                "type": "git",
                "url": "https://github.com/symfony/deprecation-contracts.git",
                "reference": reference,
            },
            "require": { "php": php },
            "autoload": { "files": ["function.php"] },
        })
    };
    let mut doc = serde_json::json!({
        "name": "socket/composer-vtag-capstone",
        "require": { VTAG_DEP: "3.5.1 || 2.5.4" },
    });
    if major < 2 {
        doc["repositories"] = serde_json::json!([
            { "packagist.org": false },
            { "type": "package", "package": release("v3.5.1", "74c71c939a79f7d5bf3c1ce9f5ea37ba0114c6f6", ">=8.1") },
            { "type": "package", "package": release("v2.5.4", "605389f2a7e5625f273b53960dc46aeaf9c62918", ">=7.1") },
        ]);
    }
    std::fs::write(
        proj.join("composer.json"),
        format!("{}\n", serde_json::to_string_pretty(&doc).unwrap()),
    )
    .unwrap();
    let update = composer(proj, &["update"], home, cache);
    if !update.status.success() {
        return composer_e2e_common::skip(
            suite,
            &format!(
                "`composer update` failed:\n{}\n{}",
                String::from_utf8_lossy(&update.stdout),
                String::from_utf8_lossy(&update.stderr)
            ),
        );
    }
    Some(())
}

/// `(major, minor)` of the composer toolchain under test.
fn composer_release() -> (u32, u32) {
    let mut probe = composer_e2e_common::composer_command();
    probe.arg("--version").arg("--no-ansi");
    cache_env::isolate(&mut probe);
    let out = probe.output().expect("run composer --version");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let version = text
        .split_whitespace()
        .skip_while(|w| *w != "version")
        .nth(1)
        .unwrap_or_else(|| panic!("unparseable `composer --version`: {text}"));
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0))
}

struct Fixture {
    tmp: tempfile::TempDir,
    pkg: FixturePkg,
    proj: PathBuf,
    purl: String,
    orig: Vec<u8>,
    patched: Vec<u8>,
    /// The pre-redirect composer.lock the real composer wrote.
    registry_lock: Vec<u8>,
    server: MockServer,
    /// Path of the hosted archive route on `server`.
    archive_path: String,
}

/// The dist zip composer downloads: every file of the installed package
/// under one GitHub-zipball-style top-level dir (composer strips a lone
/// top-level dir on both majors), with the patched entry point.
fn build_patched_zip(pkg_dir: &Path, top: &str, file_key: &str, patched: &[u8]) -> Vec<u8> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, PathBuf)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &child, out);
            } else {
                out.push((child, entry.path()));
            }
        }
    }
    let mut files = Vec::new();
    walk(pkg_dir, "", &mut files);
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.add_directory(format!("{top}/"), opts).unwrap();
        for (rel, abs) in files {
            zip.start_file(format!("{top}/{rel}"), opts).unwrap();
            let bytes = if rel == file_key {
                patched.to_vec()
            } else {
                std::fs::read(abs).unwrap()
            };
            zip.write_all(&bytes).unwrap();
        }
        zip.finish().unwrap();
    }
    buf.into_inner()
}

fn locked_version(lock: &[u8], name: &str) -> String {
    let lock: serde_json::Value = serde_json::from_slice(lock).expect("composer.lock parses");
    lock["packages"]
        .as_array()
        .expect("packages[]")
        .iter()
        .find(|p| p["name"] == name)
        .and_then(|p| p["version"].as_str())
        .unwrap_or_else(|| panic!("{name} missing from composer.lock"))
        .trim_start_matches('v')
        .to_string()
}

fn lock_entry(proj: &Path, name: &str) -> serde_json::Value {
    let lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("composer.lock")).unwrap()).unwrap();
    lock["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("{name} missing from composer.lock"))
        .clone()
}

/// A socket-patch invocation with the ambient `SOCKET_*` surface scrubbed
/// (telemetry off, no socket-cli config, `VIRTUAL_ENV` removed).
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env_remove("VIRTUAL_ENV");
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

async fn archive_hits(server: &MockServer, archive_path: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == archive_path)
        .count()
}

/// Steps 1–3. `tamper_served_archive` serves DIFFERENT bytes than the sha1
/// the reference endpoint pins — the negative twin's premise. `None` =
/// skipped (message printed).
async fn redirected_project(
    tag: &str,
    cli: RedirectCli,
    tamper_served_archive: bool,
    pkg: FixturePkg,
) -> Option<Fixture> {
    let suite = format!("{SUITE}({tag})");
    let major = composer_major(&suite)?;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let home = tmp.path().join("composer-home");
    let cache = tmp.path().join("composer-cache");
    pkg.setup(&suite, &proj, &home, &cache, major)?;
    let (name, file_key) = (pkg.name(), pkg.file_key());
    let pkg_dir = proj.join("vendor").join(name);

    let registry_lock = std::fs::read(proj.join("composer.lock")).unwrap();
    let version = locked_version(&registry_lock, name);
    let purl = format!("pkg:composer/{name}@{version}");
    let orig = std::fs::read(pkg_dir.join(file_key)).expect("installed file");
    let marker = format!("\n// SOCKET-PATCH-HOSTED-E2E-MARKER patch={UUID}\n");
    assert!(
        !String::from_utf8_lossy(&orig).contains("SOCKET-PATCH-HOSTED-E2E-MARKER"),
        "pristine install must not carry the marker"
    );
    let patched: Vec<u8> = [orig.as_slice(), marker.as_bytes()].concat();

    // 2. The patched dist archive + its sha1 (what composer.lock pins).
    let top = pkg.zip_top();
    let zip = build_patched_zip(&pkg_dir, &top, file_key, &patched);
    let sha1 = hex::encode(Sha1::digest(&zip));
    let served = if tamper_served_archive {
        build_patched_zip(&pkg_dir, &top, file_key, b"<?php // tampered\n")
    } else {
        zip
    };
    let leaf = name.rsplit('/').next().unwrap();

    let server = MockServer::start().await;
    let archive_path =
        format!("/patch/composer/{name}/{version}/{TOKEN}/{UUID}/{leaf}-{version}.zip");
    let hosted_url = format!("{}{archive_path}", server.uri());
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID, "purl": purl, "tier": "free",
                    "cveIds": [CVE], "ghsaIds": [GHSA], "severity": "high",
                    "title": "composer hosted capstone fixture"
                }]
            }],
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
                "uuid": UUID, "purl": purl,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    // composer pins `dist.shasum` — a sha1, not npm's sha512.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID: {
                "status": "granted",
                "url": hosted_url,
                "purl": purl,
                "artifacts": [{
                    "kind": "tarball",
                    "url": hosted_url,
                    "integrity": { "sha1": sha1 }
                }],
                "registryOverride": null
            }}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { file_key: {
                "beforeHash": git_sha256(&orig),
                "afterHash": git_sha256(&patched),
            }},
            "vulnerabilities": { GHSA: {
                "cves": [CVE], "summary": "composer hosted capstone vuln",
                "severity": "high", "description": "d"
            }},
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(archive_path.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_raw(served, "application/zip"))
        .mount(&server)
        .await;

    // 3. The redirect itself.
    let uri = server.uri();
    let proj_s = proj.to_str().unwrap().to_string();
    let mut argv: Vec<&str> = match cli {
        RedirectCli::ScanRedirectVex => vec![
            "scan",
            "--redirect",
            "--vex",
            "out.vex.json",
            "--vex-product",
            PRODUCT,
        ],
        RedirectCli::GetUuidHosted => vec!["get", UUID, "--mode", "hosted", "--json"],
        RedirectCli::ScanRedirectHuman => vec!["scan", "--redirect"],
    };
    if cli == RedirectCli::ScanRedirectVex {
        argv.push("--json");
    }
    argv.extend([
        "--yes",
        "--cwd",
        &proj_s,
        "--api-url",
        &uri,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ]);
    let (code, stdout, stderr) = run_socket(&proj, &argv);
    assert_eq!(
        code, 0,
        "{cli:?} failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = if cli == RedirectCli::ScanRedirectHuman {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("{cli:?} --json is not JSON ({e}):\n{stdout}"))
    };
    match cli {
        RedirectCli::ScanRedirectHuman => {
            assert!(
                stdout.contains(
                    "Reinstall from the updated lockfile (e.g. `composer install`; on Composer 1 \
                     first remove the patched packages' vendor/<vendor>/<name> directories)"
                ),
                "the next steps name the composer reinstall:\n{stdout}\n{stderr}"
            );
        }
        RedirectCli::ScanRedirectVex => {
            assert_eq!(env["redirect"]["redirected"], 1, "one redirect: {env}");
            assert_eq!(
                env["redirect"]["rewrittenFiles"][0], "composer.lock",
                "{env}"
            );
            assert_eq!(env["vex"]["statements"], 1, "in-run vex: {env}");
            let doc: serde_json::Value =
                serde_json::from_slice(&std::fs::read(proj.join("out.vex.json")).unwrap()).unwrap();
            assert_attested(&doc, &purl, UUID, Marker::Redirected, &[(GHSA, &[CVE])]);
        }
        RedirectCli::GetUuidHosted => {
            assert_eq!(env["found"], 1, "{env}");
            assert!(env.get("vex").is_none(), "get has no --vex: {env}");
        }
    }

    // composer.lock now resolves psr/log from the hosted archive, pinned.
    let entry = lock_entry(&proj, name);
    assert_eq!(
        entry["version"],
        serde_json::from_slice::<serde_json::Value>(&registry_lock).unwrap()["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == name)
            .unwrap()["version"],
        "the lock keeps its own version spelling: {entry}"
    );
    assert_eq!(entry["dist"]["type"], "zip", "{entry}");
    assert_eq!(entry["dist"]["url"], hosted_url, "{entry}");
    assert_eq!(entry["dist"]["shasum"], sha1, "{entry}");
    // The git `source` composer would fall back to when the hosted download
    // fails (composer 1, 2.2 LTS) is dropped: the archive is the only way in.
    assert!(
        entry.get("source").is_none(),
        "the redirected entry must not keep a source fallback: {entry}"
    );
    let ledger =
        std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")).expect("ledger");
    assert!(
        ledger.contains(&purl) && ledger.contains(GHSA),
        "the ledger embeds the record: {ledger}"
    );
    assert!(
        !proj.join(".socket/manifest.json").exists(),
        "hosted mode never writes a manifest"
    );
    assert!(!proj.join(".socket/blobs").exists(), "no blobs either");
    assert_eq!(
        archive_hits(&server, &archive_path).await,
        0,
        "the CLI itself never downloads the hosted archive"
    );

    Some(Fixture {
        tmp,
        pkg,
        proj,
        purl,
        orig,
        patched,
        registry_lock,
        server,
        archive_path,
    })
}

/// Step 4: a fresh checkout + cold `composer install`. Returns the checkout
/// dir and composer's output.
fn fresh_install(fx: &Fixture, tag: &str) -> (PathBuf, std::process::Output) {
    let fresh = fx.tmp.path().join(format!("fresh-{tag}"));
    fresh_checkout(&fx.proj, &fresh);
    let out = composer(
        &fresh,
        &["install"],
        &fx.tmp.path().join(format!("cold-home-{tag}")),
        &fx.tmp.path().join(format!("cold-cache-{tag}")),
    );
    (fresh, out)
}

/// Step 5 — the manifest-less legs over the fresh, really-installed
/// checkout. Blocking (subprocesses + [`PatchApi`]'s own runtime): call it
/// through `block_in_place`.
fn assert_manifestless_hosted_vex(fx: &Fixture, fresh: &Path, tag: &str) {
    let vulns: &[(&str, &[&str])] = &[(GHSA, &[CVE])];
    let purl = fx.purl.as_str();
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(UUID, purl, &[(FILE_KEY, &git_sha256(&fx.patched))], vulns),
    )]);
    let origin = fx.server.uri();
    let hosted = |run: VexRun| VexRun {
        product: Some(PRODUCT.to_string()),
        patch_server_url: Some(origin.clone()),
        ..run
    };
    let vex_in = |dir: &Path, run: VexRun| -> VexOutcome { run_vex(&binary(), dir, &run) };
    let installed = fresh.join("vendor/psr/log").join(FILE_KEY);

    // (1) the hosted flow never wrote a manifest; ledger kept.
    assert!(
        !fresh.join(".socket/manifest.json").exists(),
        "[{tag}] hosted checkout has no manifest"
    );
    strip_manifest(fresh);
    let out = vex_in(fresh, hosted(VexRun::online(&api)));
    assert_eq!(out.code, Some(0), "[{tag}] ledger kept:\n{out}");
    assert_attested(out.doc(), purl, UUID, Marker::Redirected, vulns);
    let out = vex_in(fresh, hosted(VexRun::online(&api)).via(VexVia::Apply));
    assert_eq!(out.code, Some(0), "[{tag}] apply --vex:\n{out}");
    assert_eq!(out.envelope["status"], "noManifest", "[{tag}]:\n{out}");
    assert_eq!(out.envelope["vex"]["statements"], 1, "[{tag}]:\n{out}");
    assert_attested(out.doc(), purl, UUID, Marker::Redirected, vulns);
    // The installed tree is hash-verified, not just the lock: a tampered
    // installed file un-attests even with the ledger and wiring intact.
    std::fs::write(&installed, b"<?php // tampered after install\n").unwrap();
    let out = vex_in(fresh, hosted(VexRun::online(&api)));
    assert_eq!(out.code, Some(1), "[{tag}] tampered install:\n{out}");
    assert_not_attested(&out.envelope, purl, "hash_mismatch");
    std::fs::write(&installed, &fx.patched).unwrap();

    // (4) (prepared before the ledger goes) composer.lock reverted to the
    // registry dist, ledger left behind, REAL re-install → pristine bytes.
    let reverted = fx.tmp.path().join(format!("reverted-{tag}"));
    std::fs::create_dir_all(&reverted).unwrap();
    std::fs::copy(fresh.join("composer.json"), reverted.join("composer.json")).unwrap();
    std::fs::write(reverted.join("composer.lock"), &fx.registry_lock).unwrap();
    composer_e2e_common::copy_dir_recursive(&fresh.join(".socket"), &reverted.join(".socket"));
    let install = composer(
        &reverted,
        &["install"],
        &fx.tmp.path().join(format!("reverted-home-{tag}")),
        &fx.tmp.path().join(format!("reverted-cache-{tag}")),
    );
    assert!(
        install.status.success(),
        "[{tag}] re-install from the registry lock:\n{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        std::fs::read(reverted.join("vendor/psr/log").join(FILE_KEY)).unwrap(),
        fx.orig,
        "[{tag}] the reverted install holds the pristine registry bytes"
    );
    assert!(reverted
        .join(".socket/vendor/redirect-state.json")
        .is_file());
    for (label, run) in [
        ("online", VexRun::online(&api)),
        (
            "online --no-verify",
            VexRun {
                no_verify: true,
                ..VexRun::online(&api)
            },
        ),
        (
            "offline",
            VexRun {
                proxy_url: Some(api.uri()),
                ..VexRun::offline()
            },
        ),
        (
            "offline --no-verify",
            VexRun {
                proxy_url: Some(api.uri()),
                no_verify: true,
                ..VexRun::offline()
            },
        ),
    ] {
        let out = vex_in(&reverted, hosted(run));
        assert_eq!(out.code, Some(1), "[{tag}] reverted {label}:\n{out}");
        assert_not_attested(&out.envelope, purl, "redirect_unwired");
        assert_absent(out.doc.as_ref(), purl);
    }

    // (2) ledger deleted: the lock's hosted dist + the API record.
    strip_ledgers(fresh);
    let fetched = api.view_requests(UUID);
    let out = vex_in(fresh, hosted(VexRun::online(&api)));
    assert_eq!(out.code, Some(0), "[{tag}] ledger deleted:\n{out}");
    assert_attested(out.doc(), purl, UUID, Marker::Redirected, vulns);
    assert!(
        api.view_requests(UUID) > fetched,
        "[{tag}] the record came from the API: {:?}",
        api.requests()
    );
    let out = vex_in(fresh, hosted(VexRun::online(&api)).via(VexVia::Apply));
    assert_eq!(out.code, Some(0), "[{tag}] ledger-less apply --vex:\n{out}");
    assert_attested(out.doc(), purl, UUID, Marker::Redirected, vulns);
    // Without `--patch-server-url` the loopback origin is not Socket's: no
    // reference, no fetch (`manifest_not_found`, exit 2).
    let seen = api.request_count();
    let out = vex_in(
        fresh,
        VexRun {
            product: Some(PRODUCT.to_string()),
            ..VexRun::online(&api)
        },
    );
    assert_eq!(out.code, Some(2), "[{tag}] unconfigured origin:\n{out}");
    assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
    assert_eq!(api.request_count(), seen, "[{tag}] nothing fetched");

    // (3) --offline, no ledger: record_unavailable, zero requests.
    for no_verify in [false, true] {
        let out = vex_in(
            fresh,
            hosted(VexRun {
                proxy_url: Some(api.uri()),
                no_verify,
                ..VexRun::offline()
            }),
        );
        assert_eq!(out.code, Some(1), "[{tag}] offline:\n{out}");
        assert_not_attested(&out.envelope, purl, "record_unavailable");
        assert!(out.doc.is_none(), "[{tag}]:\n{out}");
    }
    assert_eq!(
        api.request_count(),
        seen,
        "[{tag}] --offline makes zero requests: {:?}",
        api.requests()
    );
}

async fn full_chain(tag: &str, cli: RedirectCli) {
    let Some(fx) = redirected_project(tag, cli, false, FixturePkg::PsrLog).await else {
        return;
    };
    let (fresh, install) = tokio::task::block_in_place(|| fresh_install(&fx, tag));
    assert!(
        install.status.success(),
        "cold `composer install` from the hosted dist must succeed:\n{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        std::fs::read(fresh.join("vendor/psr/log").join(FILE_KEY)).unwrap(),
        fx.patched,
        "the installed file must be the hosted patched bytes"
    );
    assert!(
        archive_hits(&fx.server, &fx.archive_path).await >= 1,
        "composer must have downloaded the hosted archive"
    );
    assert!(
        composer_e2e_common::installed_packages(&fresh)
            .iter()
            .any(|p| p["name"] == DEP),
        "installed.json names {DEP}"
    );
    tokio::task::block_in_place(|| assert_manifestless_hosted_vex(&fx, &fresh, tag));
}

// multi_thread: the CLI/composer subprocesses block a worker thread while
// wiremock keeps serving the archive + API routes on the others.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real composer; the unpinned `test` job skips it, \
            the e2e job runs it with a pinned toolchain via --ignored"]
async fn composer_redirect_fresh_checkout_installs_patched_and_manifestless_vex_attests() {
    full_chain("scan", RedirectCli::ScanRedirectVex).await;
}

/// `get <uuid> --mode hosted` twin: the same redirect engine through get's
/// uuid path, the same fresh-install proof and manifest-less legs.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real composer; the unpinned `test` job skips it, \
            the e2e job runs it with a pinned toolchain via --ignored"]
async fn composer_get_uuid_hosted_fresh_checkout_and_manifestless_vex() {
    full_chain("get", RedirectCli::GetUuidHosted).await;
}

/// Negative twin: the hosted server serves bytes that do not match the sha1
/// composer.lock pins → composer's checksum verification refuses them, so
/// the pin is enforcement, not decoration.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real composer; the unpinned `test` job skips it, \
            the e2e job runs it with a pinned toolchain via --ignored"]
async fn composer_redirect_tampered_archive_fails_checksum_verification() {
    let Some(fx) = redirected_project(
        "tampered",
        RedirectCli::ScanRedirectVex,
        true,
        FixturePkg::PsrLog,
    )
    .await
    else {
        return;
    };
    let (fresh, install) = tokio::task::block_in_place(|| fresh_install(&fx, "tampered"));
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(
        !install.status.success(),
        "a tampered hosted archive must NOT install:\n{text}"
    );
    assert!(
        text.to_ascii_lowercase().contains("checksum"),
        "the refusal is composer's checksum verification:\n{text}"
    );
    assert!(
        !text.contains("Now trying to download from source"),
        "composer must have no source to fall back to (it would install the pristine \
         upstream commit):\n{text}"
    );
    assert!(
        archive_hits(&fx.server, &fx.archive_path).await >= 1,
        "the tampered archive was actually served"
    );
    assert_ne!(
        std::fs::read(fresh.join("vendor/psr/log").join(FILE_KEY)).ok(),
        Some(fx.patched.clone()),
        "nothing patched-looking may be installed"
    );
}

/// Control for WHY the redirect drops `source`: the same tampered hosted
/// archive, but with the entry's git `source` put back. Composer 1 and
/// 2.0 – 2.9 then "fall back to source" and install the PRISTINE upstream
/// commit with exit 0; 2.10+ (`source-fallback` off by default) fails.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real composer; the unpinned `test` job skips it, \
            the e2e job runs it with a pinned toolchain via --ignored"]
async fn composer_hosted_keep_source_control_documents_fallback() {
    let Some(fx) = redirected_project(
        "keep-source",
        RedirectCli::ScanRedirectVex,
        true,
        FixturePkg::PsrLog,
    )
    .await
    else {
        return;
    };
    let registry: serde_json::Value = serde_json::from_slice(&fx.registry_lock).unwrap();
    let source = registry["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == DEP)
        .and_then(|p| p.get("source"))
        .filter(|s| s.is_object())
        .cloned()
        .expect("the registry lock records a git source");
    let lock_path = fx.proj.join("composer.lock");
    let mut lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&lock_path).unwrap()).unwrap();
    let entry = lock["packages"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p["name"] == DEP)
        .unwrap();
    entry["source"] = source;
    std::fs::write(
        &lock_path,
        format!("{}\n", serde_json::to_string_pretty(&lock).unwrap()),
    )
    .unwrap();

    let (major, minor) = tokio::task::block_in_place(composer_release);
    let (fresh, install) = tokio::task::block_in_place(|| fresh_install(&fx, "keep-source"));
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(
        archive_hits(&fx.server, &fx.archive_path).await >= 1,
        "the tampered archive was tried first:\n{text}"
    );
    let installed = std::fs::read(fresh.join("vendor/psr/log").join(FILE_KEY)).ok();
    if major < 2 || minor < 10 {
        assert!(
            install.status.success(),
            "composer {major}.{minor} falls back to the git source:\n{text}"
        );
        assert_eq!(
            installed.as_deref(),
            Some(fx.orig.as_slice()),
            "composer {major}.{minor} installs the PRISTINE upstream commit:\n{text}"
        );
    } else {
        assert!(
            !install.status.success(),
            "composer {major}.{minor} has no source fallback:\n{text}"
        );
        assert_ne!(installed, Some(fx.patched.clone()), "{text}");
        assert_ne!(installed, Some(fx.orig.clone()), "{text}");
    }
}

/// A `v`-tagged release (`v3.5.1` in the lock, `3.5.1` in the purl) is
/// redirected in human mode — its next steps name the composer reinstall —
/// keeps its lock spelling, and a fresh checkout installs the patched bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real composer; the unpinned `test` job skips it, \
            the e2e job runs it with a pinned toolchain via --ignored"]
async fn composer_hosted_v_tagged_fresh_checkout_install() {
    let Some(fx) = redirected_project(
        "v-tagged",
        RedirectCli::ScanRedirectHuman,
        false,
        FixturePkg::VTagged,
    )
    .await
    else {
        return;
    };
    let (name, file_key) = (fx.pkg.name(), fx.pkg.file_key());
    let pretty = lock_entry(&fx.proj, name)["version"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(pretty.starts_with('v'), "a v-tagged lock: {pretty}");
    assert_eq!(fx.purl, format!("pkg:composer/{name}@{}", &pretty[1..]));
    let (fresh, install) = tokio::task::block_in_place(|| fresh_install(&fx, "v-tagged"));
    assert!(
        install.status.success(),
        "cold install from the hosted dist:\n{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        std::fs::read(fresh.join("vendor").join(name).join(file_key)).unwrap(),
        fx.patched,
        "the installed file is the hosted patched bytes"
    );
    let origin = fx.server.uri();
    tokio::task::block_in_place(|| {
        let vulns: &[(&str, &[&str])] = &[(GHSA, &[CVE])];
        let patched_hash = git_sha256(&fx.patched);
        let api = PatchApi::start(vec![(
            UUID.to_string(),
            patch_view(UUID, &fx.purl, &[(file_key, &patched_hash)], vulns),
        )]);
        let out = run_vex(
            &binary(),
            &fresh,
            &VexRun {
                product: Some(PRODUCT.to_string()),
                patch_server_url: Some(origin.clone()),
                ..VexRun::online(&api)
            },
        );
        assert_eq!(out.code, Some(0), "vex over the v-tagged checkout:\n{out}");
        assert_attested(out.doc(), &fx.purl, UUID, Marker::Redirected, vulns);
    });
}
