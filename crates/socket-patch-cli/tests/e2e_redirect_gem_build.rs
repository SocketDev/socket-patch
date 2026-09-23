//! Real-bundler hosted-mode capstone e2e for gem — the full-chain proof for
//! `scan --mode hosted` on the rubygems-compact-index override, and the
//! executable pin on the compact-index DEPENDENCY contract. The production
//! server HISTORICALLY violated that contract (its `/info` served no runtime
//! deps, later answered `{"error":"not_built"}`, and the
//! `/api/v1/dependencies` fallback returned a zero-byte body); the 2026-08-18
//! gem catalog republish fixed the served index, and this hermetic suite pins
//! the contract from both sides regardless of production's current state —
//! see the history section of `docs/testing/hosted-production-e2e.md`.
//!
//! Unlike the npm/cargo siblings, this suite is FULLY hermetic: the fixture
//! gems are authored here and built with the real `gem build`, and ONE
//! wiremock plays every server in the chain —
//!
//!   * the UPSTREAM rubygems registry (compact index `/versions`,
//!     `/info/<gem>`, `/names`, `/gems/<name>-<version>.gem`) serving
//!     `vuln-gem` 1.0.0 (which `require`s its runtime dependency `tiny-dep`)
//!     and `tiny-dep` 1.0.0,
//!   * the Socket PATCH REGISTRY compact index (same protocol, production's
//!     `/patch-registry/gem/<token>/<uuid>/` base) serving the PATCHED
//!     `vuln-gem` — with `/info` correctly declaring the `tiny-dep` runtime
//!     dependency and the patched `.gem`'s sha256 checksum,
//!   * the Socket patches API (batch / by-package / package-reference / view).
//!
//! The chain proven against the REAL host bundler:
//!
//!   1. `bundle install` the fixture project from the mock upstream into a
//!      project-local `vendor/bundle` (no rubygems.org, no network beyond
//!      loopback).
//!   2. `scan --mode hosted --json --vex …` (the real binary): the Gemfile
//!      gains the `source "<index-url>" do … end` block, the ledger embeds
//!      the patch record, the in-run VEX is the unverified `(redirected)`
//!      attestation.
//!   3. FRESH-CHECKOUT PROOF: only the committable files travel; an UNFROZEN
//!      `bundle install` (the flow the rewriter's `redirect_gem_frozen_install`
//!      warning prescribes) resolves the patched gem from the mock patch
//!      registry: installed bytes byte-match the patch blob, the runtime dep
//!      installs BECAUSE the registry `/info` declares it, and a require
//!      probe loads the patched code.
//!   4. POST-INSTALL VERIFIED VEX: `socket-patch vex` hash-verifies the
//!      installed tree against the ledger record.
//!
//! The `gems.rb` twin drives the same chain through bundler's modern
//! `gems.rb`/`gems.locked` spelling (which bundler prefers over `Gemfile`
//! when both exist — this pins the candidate-list + rewriter support).
//!
//! The `get <uuid> --mode hosted` twin (v3.6) drives the SAME fixture
//! through get's per-advisory selector instead of scan — same hosted engine
//! by construction (CLI_CONTRACT.md "get --mode and installed narrowing"):
//! identical Gemfile/lock rewrite + ledger, get's envelope (nested
//! `redirect`, no `downloaded`/`applied`), NO manifest, NO blobs, no --vex.
//!
//! The deps red-arm serves an `/info` shaped like production's HISTORICAL
//! defect (checksum but NO dependencies): the fresh install must fail with
//! bundler's `APIResponseMismatchError … revealed dependencies not in the
//! API` — the signature live CI saw until the 2026-08-18 server fix — so any
//! server or fixture that stops declaring runtime deps turns this suite red.
//!
//! CHECKSUMS locks (bundler >= 4 writes the section by default) come out
//! FULLY CONVERGED: patch-registry GEM section holding the dep's spec,
//! `<name> (= <ver>)!` DEPENDENCIES pin, patched CHECKSUMS sha. The flipped
//! canary proves the converged pair installs patched bytes on a fresh
//! checkout both FROZEN (`BUNDLE_FROZEN=true`, lock byte-identical — no
//! unfrozen two-step) and unfrozen (the historical exit 37 "mismatched
//! checksums" mixed-state refusal is gone; it was pinned here as a known
//! limitation until the converged rewrite landed). The depscan TS twin
//! (registry-rewrite gem.ts) must be ported to match.
//!
//! The grant-rotation capstone drives token A -> A -> B re-scans through the
//! real binary: byte-idempotent under the same grant, in-place URL refresh
//! (Gemfile source block + converged-lock remote) under a rotated one.
//!
//! MANIFEST-LESS VEX (every installing arm, `manifestless_vex_matrix`): on
//! the fresh checkout the real bundler installed — hosted never writes a
//! `.socket/manifest.json` — `vex` attests `(redirected)` from the lock +
//! ledger; with both ledgers deleted it still attests from the lockfile
//! wiring + the patch API (and so does the embedded `apply --vex`);
//! `--offline` without ledgers is `record_unavailable` with zero requests;
//! the pair reverted to its registry version is `redirect_unwired` even
//! under `--no-verify`. The main arm also proves the lock-only revert
//! (Gemfile block kept) re-converges on the next unfrozen install.
//!
//! VERSION MATRIX: the arms run on bundler 1.17 → 4.x (the CHECKSUMS arm
//! from 2.6, the CHECKSUMS-era floor; every other arm from 1.17). Pick the
//! bundler with `PATH` (CI: `ruby/setup-ruby`'s `bundler:` input) and name
//! it in `SOCKET_PATCH_BUNDLER_E2E_VERSION` (asserted) plus
//! `SOCKET_PATCH_BUNDLER_E2E_REQUIRED=1` (missing toolchain = failure) —
//! see `common/bundler_e2e.rs`. Lock shapes per era: bundler 1.17–2.1
//! writes ONE merged `GEM` section listing both remotes (attributed through
//! the Gemfile source pin), 2.2 on a separate patch-registry section; before
//! 2.2 there is no API-mismatch check (the deps red-arm's signature differs).
//!
//! Skips (with a println) when `ruby`/`gem`/`bundle` are missing (a hard
//! failure under `SOCKET_PATCH_BUNDLER_E2E_REQUIRED=1`) or the bundler is
//! below the arm's floor; everything after that is hard — no live network is
//! involved at all.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/bundler_e2e.rs"]
mod bundler_e2e;
#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

const ORG: &str = "test-org";
const DEP: &str = "vuln-gem";
const DEP_VERSION: &str = "1.0.0";
const TRANSITIVE: &str = "tiny-dep";
/// Canonical lowercase patch uuid — a path level of both the hosted artifact
/// URL and the patch-registry index URL (production shape).
const UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
/// Access-token uuid segment of the hosted URLs (opaque to the CLI — it
/// writes what the reference endpoint hands back).
const TOKEN: &str = "44444444-4444-4444-8444-444444444444";
const GHSA: &str = "GHSA-redirect-gem-real";
const PRODUCT: &str = "pkg:gem/app@1.0.0";
const PURL: &str = "pkg:gem/vuln-gem@1.0.0";

/// The runtime probe constant baked into the PATCHED lib — observable at
/// `require` time, carries the patch uuid so the assert can't pass on any
/// other content.
fn patched_marker() -> String {
    format!("PATCHED-{UUID}")
}

/// The pristine gem sources. `vuln-gem` REQUIRES its runtime dependency at
/// load time, so a resolution that drops `tiny-dep` (what a deps-less
/// registry `/info` produces) cannot pass the require probe.
fn orig_lib() -> String {
    "require \"tiny_dep\"\n\nmodule VulnGem\n  def self.status\n    \"VULNERABLE\"\n  end\n\n  DEP = TinyDep::VALUE\nend\n".to_string()
}

fn patched_lib() -> String {
    orig_lib().replace("\"VULNERABLE\"", &format!("\"{}\"", patched_marker()))
}

const TINY_LIB: &str = "module TinyDep\n  VALUE = \"tiny-ok\"\nend\n";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Run the socket-patch binary with the ambient `SOCKET_*` surface scrubbed
/// (a developer's `SOCKET_DRY_RUN=1` must not steer the assertions) and
/// `VIRTUAL_ENV` (crawler discovery input) removed.
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") && k.to_string_lossy() != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run `bundle <args>` in `cwd`: ambient `BUNDLE_*`/`GEM_*` scrubbed, caches
/// isolated, `BUNDLE_APP_CONFIG` pinned to the project's own `.bundle/`, and
/// a PER-PROJECT `BUNDLE_USER_HOME` so each stage's compact-index cache is
/// cold (the fresh-checkout install must be forced through the wiremock
/// registry, never satisfied from the scan project's cache).
fn bundle(cwd: &Path, args: &[&str]) -> Output {
    bundle_env(cwd, args, &[])
}

/// `bundle` with extra environment on top of the isolated surface — e.g.
/// `BUNDLE_FROZEN=true` for bundler's frozen/deployment contract (exit 16 on
/// any Gemfile-vs-lock drift, lock never written).
fn bundle_env(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("bundle");
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        let key = k.to_string_lossy().into_owned();
        if key.starts_with("BUNDLE_") || key.starts_with("GEM_") {
            cmd.env_remove(&k);
        }
    }
    cache_env::isolate(&mut cmd);
    cmd.env("BUNDLE_APP_CONFIG", cwd.join(".bundle"));
    cmd.env("BUNDLE_USER_HOME", cwd.join(".bundle-user-home"));
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run bundle")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// MD5 hex digest via the host ruby (`Digest::MD5`) — the compact-index
/// `/versions` line carries the md5 of each `/info/<gem>` body and bundler
/// validates it; ruby is already a suite prerequisite, so no md5 dev-dep.
fn md5_hex(bytes: &[u8]) -> String {
    let mut child = Command::new("ruby")
        .args(["-rdigest", "-e", "print Digest::MD5.hexdigest(STDIN.read)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to run ruby for md5");
    child
        .stdin
        .take()
        .expect("ruby stdin")
        .write_all(bytes)
        .expect("write md5 input");
    let out = child.wait_with_output().expect("ruby md5 output");
    assert!(out.status.success(), "ruby md5 helper failed");
    let hexstr = String::from_utf8(out.stdout).expect("md5 hex is ascii");
    assert_eq!(
        hexstr.len(),
        32,
        "md5 hex digest must be 32 chars: {hexstr}"
    );
    hexstr
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Author a gem (gemspec + one lib file) and build it with the REAL
/// `gem build`; returns the `.gem` bytes.
fn build_gem(
    stage: &Path,
    name: &str,
    version: &str,
    lib_file: &str,
    lib_content: &str,
    runtime_deps: &[&str],
) -> Vec<u8> {
    let dir = stage.join(format!("{name}-src"));
    std::fs::create_dir_all(dir.join("lib")).unwrap();
    std::fs::write(dir.join("lib").join(lib_file), lib_content).unwrap();
    let deps: String = runtime_deps
        .iter()
        .map(|d| format!("  s.add_dependency \"{d}\", \">= 0\"\n"))
        .collect();
    std::fs::write(
        dir.join(format!("{name}.gemspec")),
        format!(
            "Gem::Specification.new do |s|\n  s.name = \"{name}\"\n  s.version = \"{version}\"\n  s.summary = \"socket-patch hosted-gem capstone fixture\"\n  s.authors = [\"socket-patch e2e\"]\n  s.files = [\"lib/{lib_file}\"]\n  s.require_paths = [\"lib\"]\n{deps}end\n"
        ),
    )
    .unwrap();
    let mut cmd = Command::new("gem");
    cmd.args(["build", &format!("{name}.gemspec")])
        .current_dir(&dir);
    cache_env::isolate(&mut cmd);
    let out = cmd.output().expect("failed to run gem build");
    assert!(
        out.status.success(),
        "gem build {name} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    std::fs::read(dir.join(format!("{name}-{version}.gem"))).expect("built .gem present")
}

/// A compact-index response carrying the quoted-md5 `ETag` rubygems.org
/// serves: bundler <= 2.1 validates every `/versions` / `/info` body against
/// it and, on a mismatch (or no ETag at all), abandons the compact index for
/// the dependency API / full index — which neither index here serves, so
/// those bundlers would fail for a reason no production registry exhibits.
fn compact_index_body(body: String) -> ResponseTemplate {
    let etag = format!("\"{}\"", md5_hex(body.as_bytes()));
    ResponseTemplate::new(200)
        .insert_header("ETag", etag.as_str())
        .set_body_raw(body, "text/plain")
}

/// One gem a compact index serves: coordinates, runtime deps (compact-index
/// `name:constraint` tokens), and the `.gem` bytes the download route returns.
struct IndexGem {
    name: &'static str,
    version: &'static str,
    deps: Vec<String>,
    gem: Vec<u8>,
}

/// Mount a complete rubygems compact index under `base` (no trailing slash):
/// `/versions` (with real per-info md5 digests — bundler validates them),
/// `/info/<gem>` (deps + `checksum:<sha256-of-gem>`), `/names`, and the
/// `/gems/<name>-<version>.gem` download routes.
async fn mount_compact_index(server: &MockServer, base: &str, gems: &[IndexGem]) {
    let mut versions_body = String::from("created_at: 2026-01-01T00:00:00Z\n---\n");
    let mut names_body = String::from("---\n");
    for g in gems {
        let deps = g.deps.join(",");
        let info_body = format!(
            "---\n{} {deps}|checksum:{}\n",
            g.version,
            sha256_hex(&g.gem)
        );
        versions_body.push_str(&format!(
            "{} {} {}\n",
            g.name,
            g.version,
            md5_hex(info_body.as_bytes())
        ));
        names_body.push_str(&format!("{}\n", g.name));
        Mock::given(method("GET"))
            .and(path(format!("{base}/info/{}", g.name)))
            .respond_with(compact_index_body(info_body))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{base}/gems/{}-{}.gem", g.name, g.version)))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(g.gem.clone(), "application/octet-stream"),
            )
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("{base}/versions")))
        .respond_with(compact_index_body(versions_body))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/names")))
        .respond_with(compact_index_body(names_body))
        .mount(server)
        .await;
}

/// Everything the post-redirect legs need. `_server` keeps every registry and
/// API route alive through the fresh `bundle install`.
struct RedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    index_url: String,
    gemfile_name: &'static str,
    lock_name: &'static str,
    patched: Vec<u8>,
    /// The manifest pair as it stood BEFORE the redirect (registry wiring).
    pristine_gemfile: Vec<u8>,
    pristine_lock: Vec<u8>,
    bundler: bundler_e2e::Bundler,
    _server: MockServer,
}

/// Which manifest spelling the fixture project uses.
#[derive(Clone, Copy, PartialEq)]
enum Spelling {
    Gemfile,
    GemsRb,
}

impl Spelling {
    fn pair(self) -> (&'static str, &'static str) {
        match self {
            Spelling::Gemfile => ("Gemfile", "Gemfile.lock"),
            Spelling::GemsRb => ("gems.rb", "gems.locked"),
        }
    }
}

/// Which command drives the hosted redirect in the fixture. Both route
/// through scan's hosted engine, so the on-disk result is identical by
/// construction; the argv and the JSON envelope differ.
#[derive(Clone, Copy, PartialEq)]
enum Driver {
    /// `scan --mode hosted --json --yes --vex out.vex.json` — the original
    /// recipe with the in-run (unverified) attestation.
    ScanVex,
    /// `get <uuid> --mode hosted --json --yes` — get's per-advisory
    /// selector (v3.6). No `--vex` (get has none); the uuid path needs only
    /// the view + reference mocks and is exempt from installed narrowing.
    GetUuid,
}

impl Driver {
    fn label(self) -> &'static str {
        match self {
            Driver::ScanVex => "scan --mode hosted",
            Driver::GetUuid => "get <uuid> --mode hosted",
        }
    }
}

/// The Socket patches API reference endpoint for one grant token: granted,
/// carrying the rubygems-compact-index registry override (the identifier
/// shape the TS reference builder emits — name / version /
/// gemChecksumSha256). `limit` caps how many requests this grant answers
/// (wiremock falls through to later-mounted mocks after that), which is how
/// the rotation tests hand out token A first and the rotated token B after.
async fn mount_reference_mock(
    server: &MockServer,
    token: &str,
    patched_sha: &str,
    limit: Option<u64>,
) {
    let hosted_url = format!(
        "{}/patch/gem/{DEP}/{DEP_VERSION}/{token}/{UUID}/{DEP}-{DEP_VERSION}.gem",
        server.uri()
    );
    let index_url = format!("{}/patch-registry/gem/{token}/{UUID}/", server.uri());
    let mock = Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": hosted_url,
                    "purl": PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": hosted_url,
                        "integrity": { "sha256": patched_sha }
                    }],
                    "registryOverride": {
                        "kind": "rubygems-compact-index",
                        "indexUrl": index_url,
                        "identifiers": {
                            "name": DEP,
                            "version": DEP_VERSION,
                            "gemChecksumSha256": patched_sha,
                        }
                    }
                }
            }
        })));
    match limit {
        Some(n) => mock.up_to_n_times(n).mount(server).await,
        None => mock.mount(server).await,
    }
}

/// A bare `scan --mode hosted --json` re-scan (no VEX legs) — what a periodic
/// or CI re-run looks like.
fn run_hosted_scan(proj: &Path, api: &str) -> (i32, String, String) {
    run_socket(
        proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().expect("utf8 tmp path"),
            "--api-url",
            api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    )
}

/// Build the hermetic fixture and run the `driver` command (`scan --mode
/// hosted --vex`, or its `get <uuid> --mode hosted` twin) through the real
/// binary: author + `gem build` the three gems, mount both compact indexes
/// and the patches API, `bundle install` from the mock upstream, redirect,
/// and assert the redirect envelope + Gemfile rewrite. `checksums_lock` opts
/// the fixture lock into a CHECKSUMS section (`bundle lock --add-checksums`);
/// `registry_declares_deps` toggles the patch registry's `/info` between the
/// CORRECT contract (runtime deps declared) and today's production-like
/// deps-less answer. `rotated_token` = Some(token B) arms a grant-rotation
/// plan: the `TOKEN` grant answers the first two reference calls, token B
/// (same uuid) every later one, and the patch registry serves both token
/// paths (production keeps a grant alive until it expires). `None` = skip
/// (message already printed).
async fn redirect_scanned_project(
    tag: &str,
    spelling: Spelling,
    checksums_lock: bool,
    registry_declares_deps: bool,
    rotated_token: Option<&str>,
    driver: Driver,
) -> Option<RedirectFixture> {
    // Floors: the CHECKSUMS arm needs `bundle lock --add-checksums` (2.6+);
    // every other arm drives a CHECKSUMS-less lock, which every bundler from
    // the last 1.x (1.17) on writes. `SOCKET_PATCH_BUNDLER_E2E_{VERSION,
    // REQUIRED}` turn this into a checked version-matrix leg (see
    // `common/bundler_e2e.rs`).
    let floor = if checksums_lock { (2, 6) } else { (1, 17) };
    let bundler = bundler_e2e::gate("e2e_redirect_gem_build", tag, floor, &|c| {
        cache_env::isolate(c);
    })?;

    let tmp = tempfile::tempdir().unwrap();
    let (gemfile_name, lock_name) = spelling.pair();

    // 1. Author + build the fixture gems with the real toolchain.
    let stage = tmp.path().join("gem-stage");
    let tiny_gem = build_gem(&stage, TRANSITIVE, "1.0.0", "tiny_dep.rb", TINY_LIB, &[]);
    let vuln_gem = build_gem(
        &stage,
        DEP,
        DEP_VERSION,
        "vuln_gem.rb",
        &orig_lib(),
        &[TRANSITIVE],
    );
    let patched_gem = build_gem(
        &stage,
        DEP,
        DEP_VERSION,
        "vuln_gem.rb",
        &patched_lib(),
        &[TRANSITIVE],
    );
    let patched_sha = sha256_hex(&patched_gem);

    // 2. One wiremock plays upstream registry, patch registry, and the API.
    let server = MockServer::start().await;
    mount_compact_index(
        &server,
        "/upstream",
        &[
            IndexGem {
                name: TRANSITIVE,
                version: "1.0.0",
                deps: vec![],
                gem: tiny_gem,
            },
            IndexGem {
                name: DEP,
                version: DEP_VERSION,
                deps: vec![format!("{TRANSITIVE}:>= 0")],
                gem: vuln_gem,
            },
        ],
    )
    .await;
    // The patch registry: production's `/patch-registry/gem/<token>/<uuid>/`
    // base. The deps red-arm serves the checksum but NO runtime deps — the
    // shape a server that ignores the gem's own gemspec dependencies emits.
    let registry_base = format!("/patch-registry/gem/{TOKEN}/{UUID}");
    let index_url = format!("{}{registry_base}/", server.uri());
    mount_compact_index(
        &server,
        &registry_base,
        &[IndexGem {
            name: DEP,
            version: DEP_VERSION,
            deps: if registry_declares_deps {
                vec![format!("{TRANSITIVE}:>= 0")]
            } else {
                vec![]
            },
            gem: patched_gem.clone(),
        }],
    )
    .await;

    let orig = orig_lib().into_bytes();
    let patched = patched_lib().into_bytes();
    // Batch discovery: the crawled gem has one free patch.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "gem redirect capstone fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    // Per-package search used by the redirect selection.
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    // Reference endpoint: granted, carrying the rubygems-compact-index
    // registry override (the identifier shape the TS reference builder
    // emits — name / version / gemChecksumSha256). With a rotation plan the
    // first grant answers exactly twice (scan 1 + the same-grant re-scan),
    // then the rotated grant takes over — production rotates the token path
    // segment per request.
    mount_reference_mock(&server, TOKEN, &patched_sha, rotated_token.map(|_| 2)).await;
    if let Some(token_b) = rotated_token {
        mount_compact_index(
            &server,
            &format!("/patch-registry/gem/{token_b}/{UUID}"),
            &[IndexGem {
                name: DEP,
                version: DEP_VERSION,
                deps: if registry_declares_deps {
                    vec![format!("{TRANSITIVE}:>= 0")]
                } else {
                    vec![]
                },
                gem: patched_gem.clone(),
            }],
        )
        .await;
        mount_reference_mock(&server, token_b, &patched_sha, None).await;
    }
    // View endpoint: the patch record (REAL before/after hashes of the
    // authored vs patched lib) the redirect run persists for VEX.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "lib/vuln_gem.rb": {
                    "beforeHash": compute_git_sha256_from_bytes(&orig),
                    "afterHash": compute_git_sha256_from_bytes(&patched),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-3333"],
                    "summary": "gem redirect capstone vuln",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(&server)
        .await;

    // 3. The fixture project, installed from the MOCK upstream (hermetic).
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join(gemfile_name),
        format!("source \"{}/upstream\"\n\ngem \"{DEP}\"\n", server.uri()),
    )
    .unwrap();
    let config_args = bundler.config_local_args("path", "vendor/bundle");
    let config_args: Vec<&str> = config_args.iter().map(String::as_str).collect();
    let config = bundle(&proj, &config_args);
    assert!(
        config.status.success(),
        "bundle config set --local path failed:\n{}",
        String::from_utf8_lossy(&config.stderr)
    );
    if !checksums_lock && bundler.at_least(2, 6) {
        // Pin the bundler-2.x/3.x lock shape (no CHECKSUMS section) even on a
        // bundler >= 4 host, which writes CHECKSUMS into fresh locks by default
        // (older bundlers have no such setting and never write the section).
        let cfg = bundle(
            &proj,
            &["config", "set", "--local", "lockfile_checksums", "false"],
        );
        assert!(cfg.status.success(), "bundle config lockfile_checksums");
    }
    let install = bundle(&proj, &["install"]);
    assert!(
        install.status.success(),
        "fixture `bundle install` against the mock upstream failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    if checksums_lock {
        // Idempotent on bundler >= 4 (already written), materializes the
        // section on 2.6–3.x hosts.
        let add = bundle(&proj, &["lock", "--add-checksums"]);
        assert!(
            add.status.success(),
            "bundle lock --add-checksums failed:\n{}",
            String::from_utf8_lossy(&add.stderr)
        );
    }
    let lock_before = std::fs::read_to_string(proj.join(lock_name))
        .unwrap_or_else(|e| panic!("{lock_name} after fixture install: {e}"));
    assert_eq!(
        lock_before.contains("\nCHECKSUMS\n"),
        checksums_lock,
        "fixture lock CHECKSUMS presence must match the arm: {lock_before}"
    );

    // Pristine pre-checks (file AND absence of the marker): the post-install
    // byte asserts are circular otherwise.
    let mut ruby = Command::new("ruby");
    ruby.args(["-e", "puts Gem.ruby_api_version"]);
    cache_env::isolate(&mut ruby);
    let api = ruby.output().expect("failed to run ruby");
    assert!(api.status.success(), "ruby api version probe failed");
    let api = String::from_utf8_lossy(&api.stdout).trim().to_string();
    let installed_lib = proj
        .join("vendor/bundle/ruby")
        .join(&api)
        .join("gems")
        .join(format!("{DEP}-{DEP_VERSION}"))
        .join("lib/vuln_gem.rb");
    assert_eq!(
        std::fs::read(&installed_lib).expect("installed lib/vuln_gem.rb"),
        orig,
        "fixture install must extract the authored pristine bytes"
    );
    // The pre-redirect (registry) pair — what reverting the patch commit
    // restores; the manifest-less VEX legs revert to it.
    let pristine_gemfile = std::fs::read(proj.join(gemfile_name)).unwrap();
    let pristine_lock = lock_before.clone().into_bytes();
    // Drop the pristine materialization before redirecting: bundler never
    // refetches an already-installed gem, so with it in place the scan
    // (correctly) raises `redirect_gem_stale_install` and its same-run VEX
    // refuses to attest the purl (e2e_redirect_gem_stale_install pins that
    // contract) — the in-run attestation leg below needs the remedy that
    // warning prescribes applied first.
    std::fs::remove_dir_all(proj.join("vendor")).expect("remove the stale materialization");

    // 4. The driving command. ScanVex: scan --mode hosted --vex — the
    //    Gemfile rewrite + the in-run (unverified) attestation. GetUuid:
    //    `get <uuid> --mode hosted` — the same engine by construction, no
    //    --vex (get has none), get's envelope with the nested `redirect`.
    let api = server.uri();
    let proj_str = proj.to_str().expect("utf8 tmp path");
    let argv: Vec<&str> = match driver {
        Driver::ScanVex => vec![
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj_str,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--vex",
            "out.vex.json",
            "--vex-product",
            PRODUCT,
        ],
        Driver::GetUuid => vec![
            "get",
            UUID,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj_str,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    };
    let (code, stdout, stderr) = run_socket(&proj, &argv);
    assert_eq!(
        code,
        0,
        "{} failed.\nstdout:\n{stdout}\nstderr:\n{stderr}",
        driver.label()
    );
    assert!(
        !stdout.contains("redirect_gem_stale_install"),
        "the stale materialization was removed before the redirect:\n{stdout}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "{} --json output is not JSON: {e}\nstdout:\n{stdout}",
            driver.label()
        )
    });
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["redirect"]["mode"], "hosted", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "exactly one dep redirected: {env}"
    );
    let rewritten: Vec<&str> = env["redirect"]["rewrittenFiles"]
        .as_array()
        .expect("rewrittenFiles")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        rewritten.contains(&gemfile_name),
        "the {gemfile_name} rewrite must be reported: {env}"
    );
    let warning_codes: Vec<&str> = env["redirect"]["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    if checksums_lock {
        // CHECKSUMS-era locks converge (patch-registry GEM section +
        // dependency pin + patched sha), so the pair is frozen-installable
        // as written — the caveat would be a lie.
        assert!(
            !warning_codes.contains(&"redirect_gem_frozen_install"),
            "a converged CHECKSUMS pair must not carry the frozen-install caveat: {env}"
        );
        assert!(
            rewritten.contains(&lock_name),
            "the CHECKSUMS pin must land in {lock_name}: {env}"
        );
    } else {
        assert!(
            warning_codes.contains(&"redirect_gem_frozen_install"),
            "the frozen-install caveat must be surfaced on a mixed (no-CHECKSUMS) pair: {env}"
        );
        assert!(
            warning_codes.contains(&"redirect_gem_no_checksums_section"),
            "a no-CHECKSUMS lock cannot be pinned and must say so: {env}"
        );
        assert_eq!(
            std::fs::read_to_string(proj.join(lock_name)).unwrap(),
            lock_before,
            "a no-CHECKSUMS lock must be byte-untouched"
        );
    }
    match driver {
        Driver::ScanVex => {
            assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
            assert_eq!(
                env["vex"]["verified"], false,
                "in-run hosted VEX is attested from the ledger, not hash-verified: {env}"
            );
        }
        Driver::GetUuid => {
            // get's hosted envelope (CLI_CONTRACT.md "get --mode and
            // installed narrowing"): `found` counts the resolved patch;
            // `downloaded`/`applied` are ABSENT — nothing lands in
            // `.socket/`, the redirect ledger IS the persistence — and no
            // `vex` key (get has no --vex).
            assert_eq!(env["found"], 1, "envelope: {env}");
            assert!(
                env.get("downloaded").is_none(),
                "hosted get downloads nothing into .socket/: {env}"
            );
            assert!(
                env.get("applied").is_none(),
                "hosted get applies nothing in place: {env}"
            );
            assert!(env.get("vex").is_none(), "get has no --vex: {env}");
        }
    }

    // The Gemfile rewrite: the declaration moved into the source block whose
    // URL is the patch-registry compact index.
    let gemfile = std::fs::read_to_string(proj.join(gemfile_name)).unwrap();
    assert!(
        gemfile.contains(&format!(
            "source \"{index_url}\" do\n  gem \"{DEP}\", \"{DEP_VERSION}\"\nend"
        )),
        "{gemfile_name} must gain the patch-registry source block:\n{gemfile}"
    );
    if checksums_lock {
        let lock = std::fs::read_to_string(proj.join(lock_name)).unwrap();
        assert!(
            lock.contains(&format!("  {DEP} ({DEP_VERSION}) sha256={patched_sha}")),
            "the lock CHECKSUMS must pin the PATCHED .gem's sha256:\n{lock}"
        );
    }

    // Ledger embeds the patch record so a post-install `vex` can verify.
    let ledger = std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA),
        "redirect ledger must embed the patch record + vulnerability: {ledger}"
    );

    Some(RedirectFixture {
        tmp,
        proj,
        index_url,
        gemfile_name,
        lock_name,
        patched,
        pristine_gemfile,
        pristine_lock,
        bundler,
        _server: server,
    })
}

/// New dir named `name` holding ONLY what a git checkout would carry — the
/// manifest pair, `.socket/`, `.bundle/` — with a cold per-dir bundler home.
fn stage_fresh_checkout(fx: &RedirectFixture, name: &str) -> PathBuf {
    let fresh = fx.tmp.path().join(name);
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join(fx.gemfile_name), fresh.join(fx.gemfile_name)).unwrap();
    std::fs::copy(fx.proj.join(fx.lock_name), fresh.join(fx.lock_name)).unwrap();
    copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    copy_dir_recursive(&fx.proj.join(".bundle"), &fresh.join(".bundle"));
    assert!(
        !fresh.join("vendor").exists(),
        "fresh checkout must not carry an installed tree (test bug)"
    );
    fresh
}

/// Fresh checkout + the UNFROZEN `bundle install` the redirect prescribes on
/// a not-yet-converged lock. Returns the fresh dir and the install output.
fn fresh_checkout_bundle_install(fx: &RedirectFixture) -> (PathBuf, Output) {
    let fresh = stage_fresh_checkout(fx, "fresh");
    let install = bundle(&fresh, &["install"]);
    (fresh, install)
}

/// The installed gem's lib file under the fresh checkout's vendor/bundle.
fn fresh_installed_lib(fresh: &Path, gem_leaf: &str, lib: &str) -> PathBuf {
    let mut ruby = Command::new("ruby");
    ruby.args(["-e", "puts Gem.ruby_api_version"]);
    cache_env::isolate(&mut ruby);
    let api = ruby.output().expect("failed to run ruby");
    let api = String::from_utf8_lossy(&api.stdout).trim().to_string();
    fresh
        .join("vendor/bundle/ruby")
        .join(api)
        .join("gems")
        .join(gem_leaf)
        .join("lib")
        .join(lib)
}

/// Assert the full post-install proof: patched bytes on disk, the runtime
/// dependency present (the compact-index deps contract), and the require
/// probe resolving the patched code + the dep from the fresh vendor path.
fn assert_patched_install(fx: &RedirectFixture, fresh: &Path) {
    let installed = std::fs::read(fresh_installed_lib(
        fresh,
        &format!("{DEP}-{DEP_VERSION}"),
        "vuln_gem.rb",
    ))
    .expect("fresh install must land lib/vuln_gem.rb");
    assert_eq!(
        installed, fx.patched,
        "fresh install must hold the PATCHED bytes, byte-identical to the hosted .gem's lib"
    );
    assert_eq!(
        compute_git_sha256_from_bytes(&installed),
        compute_git_sha256_from_bytes(&fx.patched),
        "installed bytes must hash to the patch record's afterHash"
    );
    // The deps contract: `tiny-dep` reaches the install ONLY through the
    // patch registry's `/info` declaring it (the fresh resolution re-derives
    // vuln-gem's dependencies from that answer — production's deps-less
    // answer drops it, see the red-arm twin).
    assert!(
        fresh_installed_lib(fresh, &format!("{TRANSITIVE}-1.0.0"), "tiny_dep.rb").is_file(),
        "the runtime dependency must install alongside the patched gem"
    );
    let probe = bundle(
        fresh,
        &[
            "exec",
            "ruby",
            "-e",
            "require \"vuln_gem\"\nputs VulnGem.status\nputs TinyDep::VALUE\nputs $LOADED_FEATURES.grep(%r{/vuln_gem\\.rb\\z})",
        ],
    );
    assert!(
        probe.status.success(),
        "bundle exec require probe failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr),
    );
    let out = String::from_utf8_lossy(&probe.stdout).into_owned();
    assert!(
        out.contains(&patched_marker()),
        "the patched status marker must be live at require time:\n{out}"
    );
    assert!(
        out.contains("tiny-ok"),
        "the runtime dep's constant must resolve (deps contract):\n{out}"
    );
    assert!(
        out.contains("/vendor/bundle/"),
        "vuln_gem.rb must load from the fresh project-local install:\n{out}"
    );
}

// ── manifest-less VEX over the real install ───────────────────────────

/// The patch-API view's vulnerability set (see the `/view` mock).
const VULNS: &[(&str, &[&str])] = &[(GHSA, &["CVE-2026-3333"])];

/// A standalone `vex` run against the fixture's mock: the org-scoped view
/// route (the one the mock mounts), and `--patch-server-url` = the mock's
/// origin — the hosted URLs this hermetic fixture writes are on loopback,
/// not `patch.socket.dev`, and discovery only reads a Socket host or the
/// configured override.
fn vex_run(fx: &RedirectFixture) -> vex_e2e_common::VexRun {
    let uri = fx._server.uri();
    vex_e2e_common::VexRun {
        api_url: Some(uri.clone()),
        api_token: Some("fake".into()),
        org: Some(ORG.into()),
        patch_server_url: Some(uri),
        product: Some(PRODUCT.into()),
        ..vex_e2e_common::VexRun::default()
    }
}

async fn request_count(fx: &RedirectFixture) -> usize {
    fx._server
        .received_requests()
        .await
        .map(|r| r.len())
        .unwrap_or(0)
}

async fn view_requests(fx: &RedirectFixture) -> usize {
    let want = format!("/v0/orgs/{ORG}/patches/view/{UUID}");
    fx._server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == want)
        .count()
}

/// Manifest-less VEX over a fresh checkout the REAL bundler just installed
/// the patched gem into (`fresh`, whose ledger came along with the commit):
///
///   1. no `.socket/manifest.json` (hosted never writes one): `vex` attests
///      `(redirected)` from the lockfile wiring + the ledger record, hash-
///      verified against the installed tree;
///   2. both ledgers deleted too: still attested — discovery reads the
///      converged lock's patch-registry `GEM` remote and the record comes
///      from the patch API; the embedded `apply --vex` agrees;
///   3. `--offline` with no ledgers: `record_unavailable`, ZERO requests;
///   4. the manifest pair reverted to its registry version (ledgers and the
///      installed patched tree kept): `redirect_unwired`, with and without
///      `--no-verify`, online and offline.
async fn manifestless_vex_matrix(fx: &RedirectFixture, fresh: &Path) {
    use vex_e2e_common::{
        assert_absent, assert_attested, assert_not_attested, run_vex, strip_ledgers,
        strip_manifest, Marker, VexVia,
    };
    let bin = binary();
    let lock = std::fs::read_to_string(fresh.join(fx.lock_name)).unwrap();
    assert!(
        lock.contains(&format!("remote: {}", fx.index_url)),
        "the installed checkout's {} must name the patch registry (bundler {}):\n{lock}",
        fx.lock_name,
        fx.bundler.version
    );
    let ledgers = fresh.join(".socket/vendor");
    let saved = fx.tmp.path().join(format!(
        "ledgers-{}",
        fresh.file_name().unwrap().to_string_lossy()
    ));
    copy_dir_recursive(&ledgers, &saved);

    // 1. manifest-less (the ledger rides along).
    strip_manifest(fresh);
    let out = run_vex(&bin, fresh, &vex_run(fx));
    assert_eq!(
        out.code,
        Some(0),
        "manifest-less vex: {out}\n--- {}\n{lock}",
        fx.lock_name
    );
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
    assert_eq!(out.envelope["summary"]["verified"], 1, "{out}");

    // 2. no ledgers: lockfile discovery + the patch API.
    strip_ledgers(fresh);
    let views = view_requests(fx).await;
    let out = run_vex(&bin, fresh, &vex_run(fx));
    assert_eq!(
        out.code,
        Some(0),
        "ledger-less vex: {out}\n--- {}\n{lock}",
        fx.lock_name
    );
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
    assert!(
        view_requests(fx).await > views,
        "the record must come from the patch API"
    );
    let out = run_vex(&bin, fresh, &vex_run(fx).via(VexVia::Apply));
    assert_eq!(out.code, Some(0), "ledger-less apply --vex: {out}");
    assert_eq!(out.envelope["status"], "noManifest", "{out}");
    assert_eq!(out.envelope["vex"]["statements"], 1, "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
    assert!(
        !fresh.join(".socket/manifest.json").exists(),
        "vex / apply --vex must never write the manifest"
    );

    // 3. offline, no ledgers: nothing to build a statement from, no network.
    let before = request_count(fx).await;
    let mut offline = vex_run(fx);
    offline.offline = true;
    let out = run_vex(&bin, fresh, &offline);
    assert_eq!(out.code, Some(1), "offline ledger-less vex: {out}");
    assert_not_attested(&out.envelope, PURL, "record_unavailable");
    assert_eq!(request_count(fx).await, before, "--offline made requests");

    // 4. reverted to the registry pair; ledgers (and the patched install)
    //    kept.
    copy_dir_recursive(&saved, &ledgers);
    std::fs::write(fresh.join(fx.gemfile_name), &fx.pristine_gemfile).unwrap();
    std::fs::write(fresh.join(fx.lock_name), &fx.pristine_lock).unwrap();
    for (offline, no_verify) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut run = vex_run(fx);
        run.offline = offline;
        run.no_verify = no_verify;
        let out = run_vex(&bin, fresh, &run);
        let cell = format!("reverted offline={offline} no_verify={no_verify}");
        assert_eq!(out.code, Some(1), "{cell}: {out}");
        assert_not_attested(&out.envelope, PURL, "redirect_unwired");
        assert_absent(out.doc.as_ref(), PURL);
    }
}

/// The mixed pair the bundler < 2.6 rewriter leaves (and a lock-only
/// `git checkout`): the Gemfile still carries the patch-registry source
/// block, the lock resolves the gem from upstream. Bundler re-resolves from
/// the Gemfile — proven here with the REAL bundler — so the ledger keeps the
/// patch live (vex_sources `redirect_record_live` step 0), while a
/// ledger-less checkout has nothing discovery reads until that install
/// re-converges the lock, after which it attests from the lock alone.
async fn lock_only_revert_reconverges(fx: &RedirectFixture) {
    use vex_e2e_common::{assert_attested, run_vex, strip_ledgers, Marker};
    let bin = binary();
    let dir = stage_fresh_checkout(fx, "fresh-lock-only-revert");
    let install = bundle(&dir, &["install"]);
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    std::fs::write(dir.join(fx.lock_name), &fx.pristine_lock).unwrap();
    let out = run_vex(&bin, &dir, &vex_run(fx));
    assert_eq!(
        out.code,
        Some(0),
        "Gemfile-wired, lock reverted, ledger kept: {out}"
    );
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);

    strip_ledgers(&dir);
    let out = run_vex(&bin, &dir, &vex_run(fx));
    assert_eq!(
        out.code,
        Some(2),
        "no ledger and no lockfile reference: nothing to attest: {out}"
    );
    assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");

    let install = bundle(&dir, &["install"]);
    assert!(
        install.status.success(),
        "unfrozen install over the mixed pair (bundler {}):\n{}",
        fx.bundler.version,
        String::from_utf8_lossy(&install.stderr)
    );
    let lock = std::fs::read_to_string(dir.join(fx.lock_name)).unwrap();
    assert!(
        lock.contains(&format!("remote: {}", fx.index_url)),
        "bundler must re-resolve the gem from the Gemfile's patch-registry block:\n{lock}"
    );
    assert_patched_install(fx, &dir);
    let out = run_vex(&bin, &dir, &vex_run(fx));
    assert_eq!(out.code, Some(0), "re-converged, ledger-less: {out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
}

// ── the capstones ─────────────────────────────────────────────────────

// multi_thread: the CLI/gem/bundle subprocesses block a worker thread while
// wiremock keeps serving the API + both compact indexes on the others.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_fresh_checkout_bundle_install_installs_patched_bytes_and_vex_verifies() {
    let Some(fx) = redirect_scanned_project(
        "main",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVex,
    )
    .await
    else {
        return;
    };

    // FRESH-CHECKOUT PROOF: the unfrozen install the redirect prescribes
    // pulls the patched .gem from the hosted compact index.
    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "fresh-checkout `bundle install` must succeed from the patch registry.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_patched_install(&fx, &fresh);

    // The converged lock records the patch registry as the gem's source and
    // bundler's own `!` pin — the state a subsequent frozen install accepts.
    let lock = std::fs::read_to_string(fresh.join(fx.lock_name)).unwrap();
    assert!(
        lock.contains(&format!("remote: {}", fx.index_url)),
        "post-install lock must record the patch-registry source:\n{lock}"
    );
    assert!(
        lock.contains(&format!("{DEP} (= {DEP_VERSION})!")),
        "post-install lock must carry bundler's source-pinned dependency:\n{lock}"
    );

    // POST-INSTALL VERIFIED VEX: default verify mode hash-verifies the
    // installed tree against the ledger's patch record.
    let doc_path = fresh.join("doc.json");
    let (code, stdout, stderr) = run_socket(
        &fresh,
        &[
            "vex",
            "--output",
            doc_path.to_str().unwrap(),
            "--product",
            PRODUCT,
            "--cwd",
            fresh.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "post-install vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&doc_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "exactly the redirected patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL);
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (redirected)"),
        "the post-install (hash-verified) attestation must carry the (redirected) marker"
    );

    manifestless_vex_matrix(&fx, &fresh).await;
    lock_only_revert_reconverges(&fx).await;
}

/// GET-DRIVEN TWIN of the main capstone: `get <uuid> --mode hosted` (v3.6,
/// the per-advisory selector) must leave the same committable redirect
/// state as `scan --mode hosted` — same Gemfile source block, same ledger,
/// NO manifest, NO blobs — proven the same way against the REAL bundler: a
/// fresh checkout of only the committable files resolves the PATCHED gem
/// (bytes + runtime dep + require probe) from the mock patch registry.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_get_uuid_hosted_fresh_checkout_bundle_install() {
    let Some(fx) = redirect_scanned_project(
        "get-uuid",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::GetUuid,
    )
    .await
    else {
        return;
    };

    // Persistence parity with `scan --mode hosted`: the redirect ledger is
    // the ONLY .socket/ artifact — no manifest, no blobs (the fixture
    // already asserted the ledger + the Gemfile source block).
    assert!(
        !fx.proj.join(".socket/manifest.json").exists(),
        "get --mode hosted must NOT write the manifest (parity with scan --mode hosted)"
    );
    assert!(
        !fx.proj.join(".socket/blobs").exists(),
        "get --mode hosted must NOT persist blobs"
    );

    // FRESH-CHECKOUT PROOF: the unfrozen install the redirect prescribes
    // pulls the patched .gem from the hosted compact index.
    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "fresh-checkout `bundle install` must succeed from the patch registry.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_patched_install(&fx, &fresh);

    // The converged lock records the patch registry as the gem's source and
    // bundler's own `!` pin — identical to what the scan-driven capstone
    // leaves behind (parity by construction).
    let lock = std::fs::read_to_string(fresh.join(fx.lock_name)).unwrap();
    assert!(
        lock.contains(&format!("remote: {}", fx.index_url)),
        "post-install lock must record the patch-registry source:\n{lock}"
    );
    assert!(
        lock.contains(&format!("{DEP} (= {DEP_VERSION})!")),
        "post-install lock must carry bundler's source-pinned dependency:\n{lock}"
    );
    manifestless_vex_matrix(&fx, &fresh).await;
}

/// Bundler's modern `gems.rb`/`gems.locked` spelling, end to end: the
/// candidate list must read the pair, the rewriter must key its edits to it,
/// and the real bundler must install the patched gem from the redirected
/// gems.rb. Fails without the gems.rb support in either layer.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_gems_rb_spelling_redirects_and_installs() {
    let Some(fx) = redirect_scanned_project(
        "gems.rb",
        Spelling::GemsRb,
        false,
        true,
        None,
        Driver::ScanVex,
    )
    .await
    else {
        return;
    };
    assert!(
        !fx.proj.join("Gemfile").exists() && !fx.proj.join("Gemfile.lock").exists(),
        "fixture must exercise the modern spelling exclusively (test bug)"
    );

    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "fresh-checkout `bundle install` from gems.rb must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_patched_install(&fx, &fresh);
    let lock = std::fs::read_to_string(fresh.join("gems.locked")).unwrap();
    assert!(
        lock.contains(&format!("remote: {}", fx.index_url)),
        "gems.locked must converge on the patch-registry source:\n{lock}"
    );
    manifestless_vex_matrix(&fx, &fresh).await;
}

/// The compact-index DEPENDENCY contract, pinned from the red side: a patch
/// registry whose `/info` omits the gem's runtime deps (production's
/// HISTORICAL behavior until the 2026-08-18 republish fixed the served index
/// — see docs/testing/hosted-production-e2e.md's history section) BREAKS the
/// prescribed install with bundler's `APIResponseMismatchError`. If the CLI
/// or fixture ever starts tolerating that silently, this turns red.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_registry_info_without_deps_breaks_install_like_production() {
    let Some(fx) = redirect_scanned_project(
        "nodeps",
        Spelling::Gemfile,
        false,
        false,
        None,
        Driver::ScanVex,
    )
    .await
    else {
        return;
    };

    let (_fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        !install.status.success(),
        "a deps-less registry /info MUST break the fresh install — a quiet success here means \
         the dependency contract stopped being load-bearing.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    // Bundler < 4 prints the same check's message without the exception
    // class name (`Downloading vuln-gem-1.0.0 revealed dependencies not in
    // the API or the lockfile`); bundler 4 prefixes `APIResponseMismatchError`.
    // Bundler < 2.2 has no such check: its resolver trusts the index's (empty)
    // dependency list and the install dies on the dropped dep instead
    // (`Could not find tiny-dep-1.0.0 in any of the sources`).
    let signature = if fx.bundler.at_least(2, 2) {
        chatter.contains("dependencies not in the API")
            && (!fx.bundler.at_least(4, 0) || chatter.contains("APIResponseMismatchError"))
    } else {
        chatter.contains(&format!(
            "Could not find {TRANSITIVE}-1.0.0 in any of the sources"
        ))
    };
    assert!(
        signature,
        "the failure must be bundler's API-mismatch check (the live production signature), \
         not something incidental (bundler {}):\n{chatter}",
        fx.bundler.version
    );
    // Anti-vacuity: the .gem itself declares the dep, so the mismatch can
    // only come from the registry's deps-less /info.
    assert!(
        chatter.contains(TRANSITIVE),
        "the mismatch must name the dropped runtime dep:\n{chatter}"
    );
}

/// FLIPPED CANARY — CHECKSUMS locks (bundler >= 4 default) must come out
/// FULLY CONVERGED: patch-registry GEM section holding the dep's spec,
/// `<name> (= <ver>)!` DEPENDENCIES pin, patched CHECKSUMS sha (upstream sha
/// recorded in the ledger for revert). The old mixed-state rewrite (pin only,
/// GEM section left upstream) made the prescribed unfrozen install fail with
/// "Bundler found mismatched checksums" (exit 37 — the bundler-4 DEFAULT
/// lock, i.e. the mainstream hosted-gem path) and forced a frozen-install
/// two-step (exit 16) on deployment setups. The converged pair must now
/// install patched bytes BOTH ways on a fresh checkout: under
/// `BUNDLE_FROZEN=true` with the lock byte-untouched (no two-step), and
/// unfrozen (no exit 37).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_checksums_lock_converges_and_installs_frozen_and_unfrozen() {
    let Some(fx) = redirect_scanned_project(
        "checksums",
        Spelling::Gemfile,
        true,
        true,
        None,
        Driver::ScanVex,
    )
    .await
    else {
        return;
    };

    // The rewrite half: the ledger's CHECKSUMS edit must carry the UPSTREAM
    // sha as `original` (the only revert path back to the registry line).
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fx.proj.join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    let edits = ledger["edits"].as_array().expect("ledger edits");
    let edit = edits
        .iter()
        .find(|e| e["kind"] == "redirect_gemfile_lock_checksum")
        .expect("CHECKSUMS pin edit recorded in the ledger");
    assert_eq!(edit["path"], "Gemfile.lock", "edit path: {edit}");
    let original = edit["original"].as_str().expect("original recorded");
    assert!(
        original.starts_with(&format!("{DEP} ({DEP_VERSION}) sha256=")),
        "original must be the pre-edit registry line: {original}"
    );
    let lock = std::fs::read_to_string(fx.proj.join("Gemfile.lock")).unwrap();
    assert!(
        !lock.contains(original),
        "the upstream sha line must actually have been replaced (else the pin is vacuous)"
    );

    // The converged half: GEM section attribution + bundler's own `!` pin,
    // with the move and the pin recorded in the ledger.
    assert!(
        lock.contains(&format!(
            "GEM\n  remote: {}\n  specs:\n    {DEP} ({DEP_VERSION})",
            fx.index_url
        )),
        "the lock must attribute the dep to the patch-registry GEM section:\n{lock}"
    );
    assert!(
        lock.contains(&format!("  {DEP} (= {DEP_VERSION})!")),
        "DEPENDENCIES must carry the source-pinned entry:\n{lock}"
    );
    assert!(
        edits
            .iter()
            .any(|e| e["kind"] == "redirect_gemfile_lock_gem_source"),
        "the GEM-section move must be a ledger edit: {edits:?}"
    );

    // FROZEN fresh checkout: the converged pair needs no unfrozen two-step —
    // bundler's deployment contract accepts it as-is and the lock stays
    // byte-identical.
    let frozen = stage_fresh_checkout(&fx, "fresh-frozen");
    let lock_before = std::fs::read(frozen.join(fx.lock_name)).unwrap();
    let install = bundle_env(&frozen, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        install.status.success(),
        "FROZEN fresh-checkout install of the converged pair must succeed (the exit-16 \
         two-step is gone).\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_eq!(
        std::fs::read(frozen.join(fx.lock_name)).unwrap(),
        lock_before,
        "a frozen install must leave the lock byte-identical"
    );
    assert_patched_install(&fx, &frozen);
    // The converged lock is the Socket-written one here (no install-time
    // rewrite): discovery reads it AND its CHECKSUMS pin.
    manifestless_vex_matrix(&fx, &frozen).await;

    // UNFROZEN fresh checkout: the previously-pinned exit 37 "mismatched
    // checksums" refusal is gone too.
    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "unfrozen fresh-checkout install of the converged pair must succeed (the pinned \
         exit-37 mixed-state refusal is fixed).\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_patched_install(&fx, &fresh);
}

/// GRANT ROTATION, end to end (token A -> A -> B, same patch uuid): the
/// production reference endpoint rotates the grant-token path segment of the
/// index URL per request, so a periodic/CI re-scan sees a NEW index URL for
/// the SAME redirect. The re-scan must (1) be byte-idempotent under the same
/// grant, (2) refresh the source block's URL IN PLACE under a rotated grant —
/// exactly one Socket source block, a `redirect_gemfile_source_url` ledger
/// edit, no stale token anywhere — and (3) leave a pair a fresh checkout
/// installs the patched bytes from. Before the fix, the rotated re-scan
/// wrapped the old block's indented gem line in a new NESTED source block
/// (+1 nesting per re-scan), kept the stale token URL live, and still
/// reported success.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_rotated_grant_rescan_refreshes_source_block_and_installs() {
    const TOKEN_B: &str = "55555555-5555-4555-8555-555555555555";
    let Some(fx) = redirect_scanned_project(
        "rotation",
        Spelling::Gemfile,
        false,
        true,
        Some(TOKEN_B),
        Driver::ScanVex,
    )
    .await
    else {
        return;
    };
    let api = fx._server.uri();
    let index_url_b = format!("{api}/patch-registry/gem/{TOKEN_B}/{UUID}/");
    let gemfile_after_run1 = std::fs::read_to_string(fx.proj.join("Gemfile"))
        .expect("read Gemfile after initial hosted scan");
    let ledger_edits = |proj: &Path| -> Vec<serde_json::Value> {
        serde_json::from_str::<serde_json::Value>(
            &std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json"))
                .expect("read redirect ledger"),
        )
        .expect("ledger is JSON")["edits"]
            .as_array()
            .expect("ledger edits array")
            .clone()
    };
    let edits_after_run1 = ledger_edits(&fx.proj).len();

    // Re-scan 2, SAME grant: byte-idempotent, no ledger growth.
    let (code, stdout, stderr) = run_hosted_scan(&fx.proj, &api);
    assert_eq!(
        code, 0,
        "same-grant re-scan failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).expect("re-scan envelope JSON");
    assert_eq!(env["redirect"]["redirected"], 1, "envelope: {env}");
    assert_eq!(
        std::fs::read_to_string(fx.proj.join("Gemfile"))
            .expect("read Gemfile after same-grant re-scan"),
        gemfile_after_run1,
        "same-grant re-scan must leave the Gemfile byte-identical"
    );
    assert_eq!(
        ledger_edits(&fx.proj).len(),
        edits_after_run1,
        "same-grant re-scan must not grow the ledger"
    );

    // Re-scan 3, ROTATED grant (token B, same uuid): refresh in place.
    let (code, stdout, stderr) = run_hosted_scan(&fx.proj, &api);
    assert_eq!(
        code, 0,
        "rotated-grant re-scan failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).expect("rotation envelope JSON");
    assert_eq!(env["redirect"]["redirected"], 1, "envelope: {env}");
    let gemfile = std::fs::read_to_string(fx.proj.join("Gemfile"))
        .expect("read Gemfile after rotated-grant re-scan");
    assert_eq!(
        gemfile.matches("/patch-registry/gem/").count(),
        1,
        "exactly one Socket source block, never nested:\n{gemfile}"
    );
    assert!(
        gemfile.contains(&format!(
            "source \"{index_url_b}\" do\n  gem \"{DEP}\", \"{DEP_VERSION}\"\nend"
        )),
        "the block's URL must be refreshed to the rotated grant in place:\n{gemfile}"
    );
    assert!(
        !gemfile.contains(TOKEN),
        "the stale grant token must be gone from the Gemfile:\n{gemfile}"
    );
    let refresh = ledger_edits(&fx.proj)
        .into_iter()
        .find(|e| e["kind"] == "redirect_gemfile_source_url")
        .expect("rotation must be recorded as a redirect_gemfile_source_url ledger edit");
    assert_eq!(
        refresh["original"],
        serde_json::Value::String(fx.index_url.clone()),
        "refresh edit original: {refresh}"
    );
    assert_eq!(
        refresh["new"],
        serde_json::Value::String(index_url_b),
        "refresh edit new: {refresh}"
    );

    // Fresh checkout of the rotated pair: the prescribed unfrozen install
    // resolves the patched gem from the rotated registry path.
    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "fresh-checkout `bundle install` after rotation must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_patched_install(&fx, &fresh);
    // The rotated grant's URL (token B) is what the lock names now.
    let rotated = RedirectFixture {
        index_url: format!("{api}/patch-registry/gem/{TOKEN_B}/{UUID}/"),
        ..fx
    };
    manifestless_vex_matrix(&rotated, &fresh).await;
}
