//! Real-bundler hosted-mode capstone e2e for gem — the full-chain proof for
//! `scan --mode hosted` on the rubygems-compact-index override, and the
//! executable pin on the compact-index DEPENDENCY contract. The production
//! server HISTORICALLY violated that contract (its `/info` served no runtime
//! deps, later answered `{"error":"not_built"}`, and the
//! `/api/v1/dependencies` fallback returned a zero-byte body); the 2026-08-18
//! gem catalog republish fixed the served index, and this hermetic suite pins
//! the contract from both sides regardless of production's current state —
//! see `docs/testing/hosted-production-e2e.md` for the live-service counterpart.
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
//!      gains the `source "<index-url>" do … end` block, NO redirect ledger
//!      is written (v5: the manifest pair is the hosted state), the in-run
//!      VEX is the unverified `(redirected)` attestation.
//!   3. FRESH-CHECKOUT PROOF: only the committable files travel; an UNFROZEN
//!      `bundle install` (the flow the rewriter's `redirect_gem_frozen_install`
//!      warning prescribes) resolves the patched gem from the mock patch
//!      registry: installed bytes byte-match the patch blob, the runtime dep
//!      installs BECAUSE the registry `/info` declares it, and a require
//!      probe loads the patched code.
//!   4. POST-INSTALL VERIFIED VEX: `socket-patch vex` discovers the pin from
//!      the lock (`--patch-server-url` names the mock origin), fetches the
//!      record from the patch API and hash-verifies the installed tree.
//!
//! The `gems.rb` twin drives the same chain through bundler's modern
//! `gems.rb`/`gems.locked` spelling (which bundler prefers over `Gemfile`
//! when both exist — this pins the candidate-list + rewriter support).
//!
//! The `get <uuid> --mode hosted` twin (v4.0) drives the SAME fixture
//! through get's per-advisory selector instead of scan — same hosted engine
//! by construction (CLI_CONTRACT.md "get --mode and installed narrowing"):
//! identical Gemfile/lock rewrite (no ledger), get's envelope (nested
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
//! `.socket/manifest.json` nor a ledger — `vex` attests `(redirected)` from
//! the lockfile wiring + the patch API (and so does the embedded
//! `apply --vex`); `--offline` is `record_unavailable` with zero requests;
//! the pair reverted to its registry version names the patch nowhere, even
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
    run_socket_env(cwd, args, &[])
}

/// [`run_socket`] with extra environment on top of the scrubbed surface.
fn run_socket_env(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") && k.to_string_lossy() != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BUNDLE_MIRROR__") {
            cmd.env_remove(key);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    for (k, v) in envs {
        cmd.env(k, v);
    }
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

/// Copy `src` into `dst`; a missing `src` copies nothing (v5 hosted mode may
/// leave no `.socket/` at all).
fn copy_dir_recursive(src: &Path, dst: &Path) {
    if !src.exists() {
        return;
    }
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
    /// selector (v4.0). No `--vex` (get has none); the uuid path needs only
    /// the view + reference mocks and is exempt from installed narrowing.
    GetUuid,
    /// [`Driver::ScanVex`] on a dual-boot project whose `.bundle/config`
    /// sets `BUNDLE_GEMFILE: "Gemfile.next"` (#390): bundler loads
    /// `Gemfile.next`, so the run must redirect nothing and attest nothing.
    /// The fixture asserts that contract itself and yields `None`.
    ScanVexDualBoot,
    /// [`Driver::ScanVex`] on a Gemfile that declares the gem in two `group`
    /// blocks (#548): bundler accepts the duplicate, but rewriting only one
    /// declaration would leave conflicting requirements. The run must
    /// refuse, write nothing and attest nothing; the fixture asserts that
    /// and yields `None`.
    ScanVexDuplicateDeclaration,
    /// [`Driver::ScanVex`] on a Gemfile that declares the gem through
    /// `eval_gemfile` (#482): the lock lists it as a direct dependency, so
    /// appending a source block would declare it twice. Same contract as
    /// [`Driver::ScanVexDuplicateDeclaration`].
    ScanVexEvalGemfile,
    /// [`Driver::ScanVex`] on a Gemfile whose declaration continues on the
    /// next line (`gem "x",` ↵ `require: false`, #340): rewriting the first
    /// line would orphan the continuation after the source block. Same
    /// contract as [`Driver::ScanVexDuplicateDeclaration`].
    ScanVexMultiLineDeclaration,
    /// [`Driver::ScanVex`] on a Gemfile whose declaration carries an `if`
    /// modifier (#340): rewriting it would drop the condition. Same contract
    /// as [`Driver::ScanVexDuplicateDeclaration`].
    ScanVexConditionalDeclaration,
    /// A modifier adjacent to a top-level constant is still a modifier,
    /// not a hash label (`if::ENV`, #340).
    ScanVexScopedConstantModifier,
    /// A heredoc option continues beyond the declaration's physical line.
    ScanVexHeredocDeclaration,
    /// A double-quoted interpolation can itself contain a heredoc opener.
    ScanVexInterpolatedHeredocDeclaration,
    /// A second declaration joined to the gem's line by `;` (#826): the
    /// line rewrite would delete it. Same contract as
    /// [`Driver::ScanVexDuplicateDeclaration`].
    ScanVexSemicolonJoinedDeclaration,
    /// [`Driver::ScanVex`] on a declaration ending in a bare `;` and a
    /// comment (#826): a complete declaration, so it is redirected.
    ScanVexTrailingSemicolonDeclaration,
    /// [`Driver::ScanVexDualBoot`] with `BUNDLE_GEMFILE=Gemfile` exported to
    /// socket-patch too (#507): bundler's local app config outranks the
    /// environment, so bundler still loads `Gemfile.next` and the run must
    /// still redirect and attest nothing.
    ScanVexDualBootEnvGemfile,
    /// [`Driver::ScanVex`] on a bundler 4 project whose `.bundle/config`
    /// sets `lockfile custom.lock` beside a leftover `Gemfile.lock` (#749):
    /// bundler reads `custom.lock`, which the rewriter never pins, so the
    /// run must redirect nothing and attest nothing. Bundler >= 4 only; the
    /// fixture asserts the contract itself and yields `None`.
    ScanVexCustomLockfile,
    /// [`Driver::ScanVex`] on a `Gemfile` + `gems.rb` twin (#751): bundler
    /// 1.x loads the `Gemfile` and >= 2 loads `gems.rb`, and the scan cannot
    /// see which runs, so it must redirect and attest nothing and leave all
    /// four files byte-identical. Every bundler line.
    ScanVexTwin,
    /// [`Driver::ScanVex`] on a Gemfile that declares the gem inside a
    /// `group :development do … end` block (#775): hosted mode wraps it in
    /// a source block inside the group, but vendored mode cannot edit an
    /// indented declaration, so a later takeover must refuse before it
    /// un-hosts the gem.
    ScanVexGroupBlock,
    /// [`Driver::ScanVex`] on a project whose committed `.bundle/config`
    /// sets `mirror.all` (#681): bundler fetches the patch-registry source
    /// from the mirror, which serves the upstream gem. The run must refuse,
    /// write nothing and attest nothing; the fixture asserts that and
    /// yields `None`.
    ScanVexMirrorAll,
    /// Hostname app-config and exact/all environment mirrors use the same gate.
    ScanVexMirrorHost,
    /// An exact patch-source mirror set with `bundle config set --local`.
    /// Bundler 4.1 double-quotes that key in `.bundle/config` because it
    /// contains `:`.
    ScanVexMirrorSource,
    ScanVexMirrorSourceEnv,
    ScanVexMirrorAllEnv,
    /// [`Driver::ScanVex`] on a Gemfile that pulls the gem from a custom
    /// `git_source(:local)` key (#652): moved into a Socket source block the
    /// key still overrides it, so bundler keeps loading the unpatched git
    /// checkout. Same refuse-and-attest-nothing contract as
    /// [`Driver::ScanVexDuplicateDeclaration`].
    ScanVexCustomGitSource,
}

impl Driver {
    fn label(self) -> &'static str {
        match self {
            Driver::ScanVex => "scan --mode hosted",
            Driver::GetUuid => "get <uuid> --mode hosted",
            Driver::ScanVexDualBoot => "scan --mode hosted (BUNDLE_GEMFILE=Gemfile.next)",
            Driver::ScanVexDuplicateDeclaration => "scan --mode hosted (gem in two groups)",
            Driver::ScanVexEvalGemfile => "scan --mode hosted (gem via eval_gemfile)",
            Driver::ScanVexMirrorAll => "scan --mode hosted (bundler mirror.all)",
            Driver::ScanVexMirrorHost => "scan --mode hosted (bundler hostname mirror)",
            Driver::ScanVexMirrorSource => "scan --mode hosted (bundler source mirror)",
            Driver::ScanVexMirrorSourceEnv => "scan --mode hosted (bundler source mirror env)",
            Driver::ScanVexMirrorAllEnv => "scan --mode hosted (bundler mirror.all env)",
            Driver::ScanVexMultiLineDeclaration => "scan --mode hosted (multi-line gem line)",
            Driver::ScanVexConditionalDeclaration => "scan --mode hosted (gem line with `if`)",
            Driver::ScanVexScopedConstantModifier => "scan --mode hosted (gem line with `if::ENV`)",
            Driver::ScanVexHeredocDeclaration => "scan --mode hosted (heredoc gem option)",
            Driver::ScanVexInterpolatedHeredocDeclaration => {
                "scan --mode hosted (interpolated heredoc gem option)"
            }
            Driver::ScanVexDualBootEnvGemfile => {
                "scan --mode hosted (config Gemfile.next, env BUNDLE_GEMFILE=Gemfile)"
            }
            Driver::ScanVexCustomLockfile => "scan --mode hosted (lockfile custom.lock)",
            Driver::ScanVexTwin => "scan --mode hosted (Gemfile + gems.rb twin)",
            Driver::ScanVexGroupBlock => "scan --mode hosted (gem in a group block)",
            Driver::ScanVexSemicolonJoinedDeclaration => {
                "scan --mode hosted (two `;`-joined gem declarations)"
            }
            Driver::ScanVexTrailingSemicolonDeclaration => {
                "scan --mode hosted (gem line ending in `;`)"
            }
            Driver::ScanVexCustomGitSource => "scan --mode hosted (gem from a custom git_source)",
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
/// CORRECT contract (runtime deps declared) and production's HISTORICAL
/// deps-less answer (fixed by the 2026-08-18 republish). `rotated_token` =
/// Some(token B) arms a grant-rotation
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
    // Drivers that only mean something on one bundler line.
    let only = match driver {
        Driver::ScanVexCustomLockfile if !bundler.at_least(4, 0) => {
            Some("custom lockfiles need bundler >= 4")
        }
        _ => None,
    };
    if let Some(why) = only {
        println!(
            "SKIP e2e_redirect_gem_build ({tag}): bundler {}: {why}",
            bundler.version
        );
        return None;
    }

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
    let gemfile_body = match driver {
        Driver::ScanVexDuplicateDeclaration => format!(
            "source \"{}/upstream\"\n\ngroup :development do\n  gem \"{DEP}\"\nend\n\n\
             group :test do\n  gem \"{DEP}\"\nend\n",
            server.uri()
        ),
        Driver::ScanVexGroupBlock => format!(
            "source \"{}/upstream\"\n\ngroup :development do\n  gem \"{DEP}\"\nend\n",
            server.uri()
        ),
        Driver::ScanVexEvalGemfile => {
            std::fs::write(proj.join("Gemfile.common"), format!("gem \"{DEP}\"\n")).unwrap();
            format!(
                "source \"{}/upstream\"\n\neval_gemfile \"Gemfile.common\"\n",
                server.uri()
            )
        }
        Driver::ScanVexCustomGitSource => {
            // The gem's pristine source as a local git repo, reached through
            // a custom `git_source` key: bundler resolves it from a `GIT`
            // section, never from the registry a Socket source block names.
            let repos = tmp.path().join("repos");
            let repo = repos.join(DEP);
            copy_dir_recursive(&stage.join(format!("{DEP}-src")), &repo);
            for args in [
                &["init", "-q"][..],
                &["add", "-A"][..],
                &[
                    "-c",
                    "user.name=socket-patch e2e",
                    "-c",
                    "user.email=e2e@socket.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ][..],
            ] {
                let out = Command::new("git")
                    .args(args)
                    .current_dir(&repo)
                    .output()
                    .expect("failed to run git");
                assert!(
                    out.status.success(),
                    "git {args:?} failed:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            format!(
                "source \"{}/upstream\"\n\n\
                 git_source(:local) {{ |r| \"{}/#{{r}}\" }}\n\n\
                 gem \"{DEP}\", local: \"{DEP}\"\n",
                server.uri(),
                repos.display()
            )
        }
        Driver::ScanVexMultiLineDeclaration => format!(
            "source \"{}/upstream\"\n\ngem \"{DEP}\",\n  require: false\n",
            server.uri()
        ),
        Driver::ScanVexConditionalDeclaration => format!(
            "source \"{}/upstream\"\n\ngem \"{DEP}\" if ENV[\"WITH_VULN\"] != \"0\"\n",
            server.uri()
        ),
        Driver::ScanVexScopedConstantModifier => format!(
            "source \"{}/upstream\"\n\ngem \"{DEP}\", \"{DEP_VERSION}\" if::ENV[\"WITH_VULN\"] != \"0\"\n",
            server.uri()
        ),
        Driver::ScanVexHeredocDeclaration => format!(
            "source \"{}/upstream\"\n\ngem \"{DEP}\", require: <<~REQUIRE_PATH.chomp\n  vuln_gem\nREQUIRE_PATH\n",
            server.uri()
        ),
        Driver::ScanVexInterpolatedHeredocDeclaration => format!(
            "source \"{}/upstream\"\n\ngem \"{DEP}\", require: \"#{{<<~REQUIRE_PATH}}\".chomp\n  vuln_gem\nREQUIRE_PATH\n",
            server.uri()
        ),
        Driver::ScanVexSemicolonJoinedDeclaration => format!(
            "source \"{}/upstream\"\n\ngem \"{DEP}\", \"{DEP_VERSION}\"; gem \"{TRANSITIVE}\", \"1.0.0\"\n",
            server.uri()
        ),
        Driver::ScanVexTrailingSemicolonDeclaration => format!(
            "source \"{}/upstream\"\n\ngem \"{DEP}\"; # the vulnerable one\n",
            server.uri()
        ),
        _ => format!("source \"{}/upstream\"\n\ngem \"{DEP}\"\n", server.uri()),
    };
    std::fs::write(proj.join(gemfile_name), gemfile_body).unwrap();
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
    if driver == Driver::ScanVexCustomGitSource {
        // Bundler checks a git gem out under `bundler/gems/`, and the lock
        // attributes it to a `GIT` section — the shape the scan must refuse.
        assert!(
            lock_before.starts_with("GIT\n") && !installed_lib.exists(),
            "fixture must resolve the gem from git: {lock_before}"
        );
    } else {
        assert_eq!(
            std::fs::read(&installed_lib).expect("installed lib/vuln_gem.rb"),
            orig,
            "fixture install must extract the authored pristine bytes"
        );
    }
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
    let dual_boot = matches!(
        driver,
        Driver::ScanVexDualBoot | Driver::ScanVexDualBootEnvGemfile
    );
    if dual_boot {
        // The next-Rails dual boot: a `Gemfile.next` pair that bundler loads
        // through the committed `.bundle/config`.
        std::fs::copy(proj.join(gemfile_name), proj.join("Gemfile.next")).unwrap();
        std::fs::copy(proj.join(lock_name), proj.join("Gemfile.next.lock")).unwrap();
        let args = bundler.config_local_args("gemfile", "Gemfile.next");
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let cfg = bundle(&proj, &args);
        assert!(
            cfg.status.success(),
            "bundle config set --local gemfile failed:\n{}",
            String::from_utf8_lossy(&cfg.stderr)
        );
    }
    let custom_lockfile = driver == Driver::ScanVexCustomLockfile;
    if custom_lockfile {
        // `bundle config set --local lockfile custom.lock`; the default
        // lock stays behind as a leftover bundler 4 ignores.
        std::fs::copy(proj.join(lock_name), proj.join("custom.lock")).unwrap();
        let args = bundler.config_local_args("lockfile", "custom.lock");
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let cfg = bundle(&proj, &args);
        assert!(
            cfg.status.success(),
            "bundle config set --local lockfile failed:\n{}",
            String::from_utf8_lossy(&cfg.stderr)
        );
    }
    let twin = driver == Driver::ScanVexTwin;
    if twin {
        // Identical twins: which pair installs depends only on the bundler
        // that runs.
        std::fs::copy(proj.join(gemfile_name), proj.join("gems.rb")).unwrap();
        std::fs::copy(proj.join(lock_name), proj.join("gems.locked")).unwrap();
    }
    // Synthetic credentials must never appear in the scan's automatic
    // diagnostics. The loopback mirror itself serves the unpatched gem.
    let mirror = format!("{}/upstream/", server.uri()).replacen(
        "http://",
        "http://review-user:review-secret@",
        1,
    );
    if matches!(
        driver,
        Driver::ScanVexMirrorAll | Driver::ScanVexMirrorHost | Driver::ScanVexMirrorSource
    ) {
        let setting = match driver {
            Driver::ScanVexMirrorAll => "mirror.all".to_owned(),
            Driver::ScanVexMirrorHost => "mirror.127.0.0.1".to_owned(),
            _ => format!("mirror.{index_url}"),
        };
        let args = bundler.config_local_args(&setting, &mirror);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let cfg = bundle(&proj, &args);
        assert!(
            cfg.status.success(),
            "bundle config set --local mirror.all failed:\n{}",
            String::from_utf8_lossy(&cfg.stderr)
        );
    }
    let argv: Vec<&str> = match driver {
        Driver::ScanVex
        | Driver::ScanVexMirrorAll
        | Driver::ScanVexMirrorHost
        | Driver::ScanVexMirrorSource
        | Driver::ScanVexMirrorSourceEnv
        | Driver::ScanVexMirrorAllEnv
        | Driver::ScanVexCustomLockfile
        | Driver::ScanVexTwin
        | Driver::ScanVexDualBoot
        | Driver::ScanVexDualBootEnvGemfile
        | Driver::ScanVexDuplicateDeclaration
        | Driver::ScanVexEvalGemfile
        | Driver::ScanVexGroupBlock
        | Driver::ScanVexCustomGitSource
        | Driver::ScanVexMultiLineDeclaration
        | Driver::ScanVexConditionalDeclaration
        | Driver::ScanVexScopedConstantModifier
        | Driver::ScanVexHeredocDeclaration
        | Driver::ScanVexInterpolatedHeredocDeclaration
        | Driver::ScanVexSemicolonJoinedDeclaration
        | Driver::ScanVexTrailingSemicolonDeclaration => vec![
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
    let mirror_source_key = format!(
        "BUNDLE_MIRROR__{}",
        index_url
            .replace('.', "__")
            .replace('-', "___")
            .to_uppercase()
    );
    let socket_env: &[(&str, &str)] = match driver {
        Driver::ScanVexDualBootEnvGemfile => &[("BUNDLE_GEMFILE", "Gemfile")],
        Driver::ScanVexMirrorSourceEnv => &[(&mirror_source_key, &mirror)],
        Driver::ScanVexMirrorAllEnv => &[("BUNDLE_MIRROR__ALL", &mirror)],
        _ => &[],
    };
    let (code, stdout, stderr) = run_socket_env(&proj, &argv, socket_env);
    if dual_boot {
        let env: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
        // `--vex` with nothing to attest is an error: the run must not
        // look like a successful, attested patch.
        assert_ne!(code, 0, "nothing was patched or attested: {env}");
        assert_eq!(
            env["error"]["code"], "manifest_not_found",
            "envelope: {env}"
        );
        assert_dual_boot_redirects_nothing(&env, &proj, &pristine_gemfile, &pristine_lock);
        return None;
    }
    if custom_lockfile {
        assert_custom_lockfile_redirects_nothing(
            &bundler,
            "redirect_gem_bundle_lockfile_unsupported",
            (code, &stdout, &stderr),
            &proj,
            &[
                ("Gemfile", &pristine_gemfile),
                ("Gemfile.lock", &pristine_lock),
                ("custom.lock", &pristine_lock),
            ],
        );
        return None;
    }
    if twin {
        assert_custom_lockfile_redirects_nothing(
            &bundler,
            "redirect_gem_twin_manifest_ambiguous",
            (code, &stdout, &stderr),
            &proj,
            &[
                ("Gemfile", &pristine_gemfile),
                ("Gemfile.lock", &pristine_lock),
                ("gems.rb", &pristine_gemfile),
                ("gems.locked", &pristine_lock),
            ],
        );
        return None;
    }
    if let Some(warning) = match driver {
        Driver::ScanVexDuplicateDeclaration => Some("redirect_gem_declared_more_than_once"),
        Driver::ScanVexEvalGemfile => Some("redirect_gem_declaration_not_visible"),
        Driver::ScanVexMirrorAll
        | Driver::ScanVexMirrorHost
        | Driver::ScanVexMirrorSource
        | Driver::ScanVexMirrorSourceEnv
        | Driver::ScanVexMirrorAllEnv => Some("redirect_gem_mirror_overrides_source"),
        Driver::ScanVexCustomGitSource => Some("redirect_gem_source_option"),
        Driver::ScanVexMultiLineDeclaration
        | Driver::ScanVexConditionalDeclaration
        | Driver::ScanVexScopedConstantModifier
        | Driver::ScanVexHeredocDeclaration
        | Driver::ScanVexInterpolatedHeredocDeclaration
        | Driver::ScanVexSemicolonJoinedDeclaration => {
            Some("redirect_gem_unrecognized_declaration")
        }
        _ => None,
    } {
        for secret in ["review-user", "review-secret"] {
            assert!(
                !stdout.contains(secret) && !stderr.contains(secret),
                "mirror credential disclosed"
            );
        }
        assert_unwirable_declaration_redirects_nothing(
            &proj,
            &bundler,
            warning,
            (code, &stdout, &stderr),
            &pristine_gemfile,
            &pristine_lock,
        );
        return None;
    }
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
        Driver::ScanVex
        | Driver::ScanVexGroupBlock
        | Driver::ScanVexTrailingSemicolonDeclaration => {
            assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
            assert_eq!(
                env["vex"]["verified"], false,
                "in-run hosted VEX is attested from this run's fetched record, not hash-verified: {env}"
            );
        }
        Driver::ScanVexDualBoot
        | Driver::ScanVexDualBootEnvGemfile
        | Driver::ScanVexCustomLockfile
        | Driver::ScanVexTwin
        | Driver::ScanVexDuplicateDeclaration
        | Driver::ScanVexEvalGemfile
        | Driver::ScanVexMirrorAll
        | Driver::ScanVexMirrorHost
        | Driver::ScanVexMirrorSource
        | Driver::ScanVexMirrorSourceEnv
        | Driver::ScanVexMirrorAllEnv
        | Driver::ScanVexCustomGitSource
        | Driver::ScanVexMultiLineDeclaration
        | Driver::ScanVexConditionalDeclaration
        | Driver::ScanVexScopedConstantModifier
        | Driver::ScanVexHeredocDeclaration
        | Driver::ScanVexInterpolatedHeredocDeclaration
        | Driver::ScanVexSemicolonJoinedDeclaration => {
            unreachable!("asserted and returned above")
        }
        Driver::GetUuid => {
            // get's hosted envelope (CLI_CONTRACT.md "get --mode and
            // installed narrowing"): `found` counts the resolved patch;
            // `downloaded`/`applied` are ABSENT — nothing lands in
            // `.socket/`, the lockfile IS the persistence — and no
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

    // v5: hosted mode writes no ledger — the manifest pair is the state.
    assert_no_redirect_ledger(&proj);

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

/// #482 / #548: a Gemfile whose declarations of the gem the rewriter cannot
/// edit as one (two `group` blocks, an `eval_gemfile`d file). The scan names
/// the refusal, leaves the pair byte-identical and attests nothing, and the
/// real bundler still installs the project (before the fix the Gemfile was
/// left declaring the gem twice and every install exited 4).
fn assert_unwirable_declaration_redirects_nothing(
    proj: &Path,
    bundler: &bundler_e2e::Bundler,
    warning: &str,
    (code, stdout, stderr): (i32, &str, &str),
    pristine_gemfile: &[u8],
    pristine_lock: &[u8],
) {
    let env: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
    assert!(
        stdout.contains(warning),
        "the refusal must be named ({warning}): {env}"
    );
    assert_ne!(code, 0, "nothing was patched or attested: {env}");
    assert!(
        env["vex"]["statements"].as_u64().unwrap_or(0) == 0,
        "nothing may be attested: {env}"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile")).unwrap(),
        pristine_gemfile,
        "the Gemfile must be byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        pristine_lock,
        "the lock must be byte-identical"
    );
    let install = bundle(proj, &["install"]);
    assert!(
        install.status.success(),
        "bundler {} must still install the untouched project:\n{}",
        bundler.version,
        String::from_utf8_lossy(&install.stderr)
    );
}

/// The contract of a hosted scan that must refuse every gem: #749's
/// `custom.lock` named in `.bundle/config` (bundler 4), or #751's
/// `Gemfile` + `gems.rb` twin. The scan reports `refusal`, redirects and
/// attests nothing, leaves every one of `files` byte-identical, and bundler
/// still installs the untouched project frozen.
fn assert_custom_lockfile_redirects_nothing(
    bundler: &bundler_e2e::Bundler,
    refusal: &str,
    (code, stdout, stderr): (i32, &str, &str),
    proj: &Path,
    files: &[(&str, &[u8])],
) {
    let env: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
    let warning_codes: Vec<&str> = env["redirect"]["warnings"]
        .as_array()
        .map(|a| a.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        warning_codes.contains(&refusal),
        "the {refusal} refusal must be reported: {env}"
    );
    assert_ne!(code, 0, "nothing was patched or attested: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 0,
        "nothing redirected: {env}"
    );
    assert!(
        env["vex"]["statements"].as_u64().unwrap_or(0) == 0,
        "no in-run attestation for a lock that was never pinned: {env}"
    );
    for (file, want) in files {
        assert_eq!(
            std::fs::read(proj.join(file)).unwrap(),
            *want,
            "{file} must be byte-untouched"
        );
    }
    let args = bundler.config_local_args("frozen", "true");
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    assert!(bundle(proj, &args).status.success());
    let install = bundle(proj, &["install"]);
    assert!(
        install.status.success(),
        "bundler {} must still install the untouched project frozen:\n{}",
        bundler.version,
        String::from_utf8_lossy(&install.stderr)
    );
}

/// #390's contract on a `BUNDLE_GEMFILE: Gemfile.next` project: the hosted
/// scan names the setting, rewrites neither the `Gemfile` pair (which
/// bundler ignores) nor `Gemfile.next`, and its in-run VEX attests nothing.
/// Then the real bundler, loading `Gemfile.next`, resolves the upstream gem
/// (nothing pretends otherwise).
fn assert_dual_boot_redirects_nothing(
    env: &serde_json::Value,
    proj: &Path,
    pristine_gemfile: &[u8],
    pristine_lock: &[u8],
) {
    let warning_codes: Vec<&str> = env["redirect"]["warnings"]
        .as_array()
        .map(|a| a.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        warning_codes.contains(&"redirect_gem_bundle_gemfile_unsupported"),
        "the BUNDLE_GEMFILE refusal must be reported: {env}"
    );
    assert!(
        !warning_codes.contains(&"redirect_gem_no_gemfile"),
        "the refusal names its real cause, not a missing Gemfile: {env}"
    );
    assert_eq!(
        env["redirect"]["redirected"], 0,
        "nothing redirected: {env}"
    );
    assert!(
        env["vex"]["statements"].as_u64().unwrap_or(0) == 0,
        "no in-run attestation for a gem bundler installs unpatched: {env}"
    );
    for (file, want) in [
        ("Gemfile", pristine_gemfile),
        ("Gemfile.lock", pristine_lock),
        ("Gemfile.next", pristine_gemfile),
        ("Gemfile.next.lock", pristine_lock),
    ] {
        assert_eq!(
            std::fs::read(proj.join(file)).unwrap(),
            want,
            "{file} must be byte-untouched"
        );
    }
    assert_no_redirect_ledger(proj);
}

/// v5 hosted mode never writes `.socket/vendor/redirect-state.json`.
fn assert_no_redirect_ledger(proj: &Path) {
    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "v5 hosted mode must not write the redirect ledger"
    );
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
    // vuln-gem's dependencies from that answer — a deps-less answer
    // (production's historical defect, reproduced by the red-arm twin) drops
    // it).
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
/// the patched gem into (`fresh`):
///
///   1. no `.socket/manifest.json` and no ledger (hosted writes neither):
///      `vex` attests `(redirected)` — discovery reads the converged lock's
///      patch-registry `GEM` remote and the record comes from the patch
///      API, hash-verified against the installed tree; the embedded
///      `apply --vex` agrees;
///   2. `--offline`: no local record → `record_unavailable`, ZERO requests;
///   3. the manifest pair reverted to its registry version (the installed
///      patched tree kept): nothing names the patch any more
///      (`manifest_not_found`), with and without `--no-verify`, online and
///      offline.
async fn manifestless_vex_matrix(fx: &RedirectFixture, fresh: &Path) {
    use vex_e2e_common::{
        assert_absent, assert_attested, assert_not_attested, run_vex, strip_manifest, Marker,
        VexVia,
    };
    let bin = binary();
    let lock = std::fs::read_to_string(fresh.join(fx.lock_name)).unwrap();
    assert!(
        lock.contains(&format!("remote: {}", fx.index_url)),
        "the installed checkout's {} must name the patch registry (bundler {}):\n{lock}",
        fx.lock_name,
        fx.bundler.version
    );
    assert_no_redirect_ledger(fresh);

    // 1. manifest-less, ledger-less: lockfile discovery + the patch API.
    strip_manifest(fresh);
    let views = view_requests(fx).await;
    let out = run_vex(&bin, fresh, &vex_run(fx));
    assert_eq!(
        out.code,
        Some(0),
        "manifest-less vex: {out}\n--- {}\n{lock}",
        fx.lock_name
    );
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
    assert_eq!(out.envelope["summary"]["verified"], 1, "{out}");
    assert!(
        view_requests(fx).await > views,
        "the record must come from the patch API"
    );
    let out = run_vex(&bin, fresh, &vex_run(fx).via(VexVia::Apply));
    assert_eq!(out.code, Some(0), "manifest-less apply --vex: {out}");
    assert_eq!(out.envelope["status"], "noManifest", "{out}");
    assert_eq!(out.envelope["vex"]["statements"], 1, "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
    assert!(
        !fresh.join(".socket/manifest.json").exists(),
        "vex / apply --vex must never write the manifest"
    );

    // 2. offline: no local record to build a statement from, no network.
    let before = request_count(fx).await;
    let mut offline = vex_run(fx);
    offline.offline = true;
    let out = run_vex(&bin, fresh, &offline);
    assert_eq!(out.code, Some(1), "offline vex: {out}");
    assert_not_attested(&out.envelope, PURL, "record_unavailable");
    assert_eq!(request_count(fx).await, before, "--offline made requests");

    // 3. reverted to the registry pair (the patched install kept): no lock
    //    names the patch, and hosted mode keeps no ledger to remember it.
    std::fs::write(fresh.join(fx.gemfile_name), &fx.pristine_gemfile).unwrap();
    std::fs::write(fresh.join(fx.lock_name), &fx.pristine_lock).unwrap();
    for (offline, no_verify) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut run = vex_run(fx);
        run.offline = offline;
        run.no_verify = no_verify;
        let out = run_vex(&bin, fresh, &run);
        let cell = format!("reverted offline={offline} no_verify={no_verify}");
        assert_eq!(out.code, Some(2), "{cell}: {out}");
        assert_eq!(
            out.envelope["error"]["code"], "manifest_not_found",
            "{cell}: {out}"
        );
        assert_absent(out.doc.as_ref(), PURL);
    }
}

/// The mixed pair the bundler < 2.6 rewriter leaves (and a lock-only
/// `git checkout`): the Gemfile still carries the patch-registry source
/// block, the lock resolves the gem from upstream. Bundler re-resolves from
/// the Gemfile — proven here with the REAL bundler. v5 keeps no ledger, so
/// the mixed checkout has nothing discovery reads (lockfile pins only) until
/// that install re-converges the lock, after which it attests from the lock
/// alone.
async fn lock_only_revert_reconverges(fx: &RedirectFixture) {
    use vex_e2e_common::{assert_attested, run_vex, Marker};
    let bin = binary();
    let dir = stage_fresh_checkout(fx, "fresh-lock-only-revert");
    let install = bundle(&dir, &["install"]);
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    std::fs::write(dir.join(fx.lock_name), &fx.pristine_lock).unwrap();
    assert_no_redirect_ledger(&dir);
    let out = run_vex(&bin, &dir, &vex_run(fx));
    assert_eq!(
        out.code,
        Some(2),
        "Gemfile-wired, lock reverted: no lockfile reference, nothing to attest: {out}"
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
    assert_eq!(out.code, Some(0), "re-converged: {out}");
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
    // installed tree against the patch API's record (v5: no ledger — the pin
    // comes from the lock on the `--patch-server-url` origin).
    let doc_path = fresh.join("doc.json");
    let server = fx._server.uri();
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
            "--patch-server-url",
            &server,
            "--api-url",
            &server,
            "--org",
            ORG,
            "--api-token",
            "fake",
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

/// GET-DRIVEN TWIN of the main capstone: `get <uuid> --mode hosted` (v4.0,
/// the per-advisory selector) must leave the same committable redirect
/// state as `scan --mode hosted` — same Gemfile source block, NO ledger,
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

    // Persistence parity with `scan --mode hosted`: nothing lands in
    // .socket/ — no ledger, no manifest, no blobs (the fixture already
    // asserted the missing ledger + the Gemfile source block).
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

/// One patched gem a later patch generation serves: its uuid, the patched
/// `.gem`, and the lib file's before/after bytes for the view record.
struct GenerationGem {
    name: &'static str,
    uuid: &'static str,
    deps: Vec<String>,
    lib_file: &'static str,
    orig: String,
    patched: String,
    gem: Vec<u8>,
}

/// Layer a new patch generation over the fixture's API mocks (wiremock
/// serves the lowest `priority` first): the batch, by-package, reference and
/// view routes answer with `gems`, and each uuid gets its own patch-registry
/// compact index under the fixture's grant token.
async fn mount_patch_generation(server: &MockServer, priority: u8, gems: &[GenerationGem]) {
    let purl = |g: &GenerationGem| format!("pkg:gem/{}@{DEP_VERSION}", g.name);
    for g in gems {
        mount_compact_index(
            server,
            &format!("/patch-registry/gem/{TOKEN}/{}", g.uuid),
            &[IndexGem {
                name: g.name,
                version: DEP_VERSION,
                deps: g.deps.clone(),
                gem: g.gem.clone(),
            }],
        )
        .await;
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{}", g.uuid)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": g.uuid,
                "purl": purl(g),
                "publishedAt": "2026-02-01T00:00:00Z",
                "files": {
                    format!("lib/{}", g.lib_file): {
                        "beforeHash": compute_git_sha256_from_bytes(g.orig.as_bytes()),
                        "afterHash": compute_git_sha256_from_bytes(g.patched.as_bytes()),
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
            .with_priority(priority)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{}.*$",
                g.name
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": g.uuid, "purl": purl(g),
                    "publishedAt": "2026-02-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            })))
            .with_priority(priority)
            .mount(server)
            .await;
    }
    let packages: Vec<serde_json::Value> = gems
        .iter()
        .map(|g| {
            serde_json::json!({
                "purl": purl(g),
                "patches": [{
                    "uuid": g.uuid, "purl": purl(g), "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "gem redirect capstone fixture"
                }]
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": packages,
            "canAccessPaidPatches": false,
        })))
        .with_priority(priority)
        .mount(server)
        .await;
    let results: serde_json::Map<String, serde_json::Value> = gems
        .iter()
        .map(|g| {
            let sha = sha256_hex(&g.gem);
            let hosted_url = format!(
                "{}/patch/gem/{}/{DEP_VERSION}/{TOKEN}/{}/{}-{DEP_VERSION}.gem",
                server.uri(),
                g.name,
                g.uuid,
                g.name
            );
            let index_url = format!("{}/patch-registry/gem/{TOKEN}/{}/", server.uri(), g.uuid);
            (
                g.uuid.to_string(),
                serde_json::json!({
                    "status": "granted",
                    "url": hosted_url,
                    "purl": purl(g),
                    "artifacts": [{
                        "kind": "tarball",
                        "url": hosted_url,
                        "integrity": { "sha256": sha }
                    }],
                    "registryOverride": {
                        "kind": "rubygems-compact-index",
                        "indexUrl": index_url,
                        "identifiers": {
                            "name": g.name,
                            "version": DEP_VERSION,
                            "gemChecksumSha256": sha,
                        }
                    }
                }),
            )
        })
        .collect();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results })),
        )
        .with_priority(priority)
        .mount(server)
        .await;
}

/// The `remote:` URLs of a lock's `GEM` sections, in file order.
fn gem_remotes(lock: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_gem = false;
    for line in lock.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            in_gem = line == "GEM";
        } else if let Some(url) = line.strip_prefix("  remote: ").filter(|_| in_gem) {
            out.push(url);
        }
    }
    out
}

/// #1186: two gems hosted in their own patch-registry `GEM` sections, then a
/// superseding patch for one of them whose new uuid sorts AFTER its
/// sibling. The re-scan must move the refreshed section to where bundler
/// writes it (sections sorted by remote URL): a converged CHECKSUMS lock
/// that `bundle lock` leaves byte-identical and a cold frozen install
/// accepts. An in-place refresh left the sections out of order, and every
/// frozen install on bundler 4.0.19+ exited 16 ("Your lockfile needs to be
/// updated, but it can't be because frozen mode is set").
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_superseding_patch_keeps_gem_sections_in_bundler_order() {
    let Some(fx) = redirect_scanned_project(
        "supersede-section-order",
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
    const VULN_GEN2: &str = "10000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const TINY_GEN2: &str = "80000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const VULN_GEN3: &str = "9a9a9a9a-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let stage = fx.tmp.path().join("generation-stage");
    let vuln = |uuid: &'static str, lib: String| {
        let gem = build_gem(
            &stage.join(uuid),
            DEP,
            DEP_VERSION,
            "vuln_gem.rb",
            &lib,
            &[TRANSITIVE],
        );
        GenerationGem {
            name: DEP,
            uuid,
            deps: vec![format!("{TRANSITIVE}:>= 0")],
            lib_file: "vuln_gem.rb",
            orig: orig_lib(),
            patched: lib,
            gem,
        }
    };
    let tiny_patched = TINY_LIB.replace("tiny-ok", "tiny-patched");
    let tiny = GenerationGem {
        name: TRANSITIVE,
        uuid: TINY_GEN2,
        deps: vec![],
        lib_file: "tiny_dep.rb",
        orig: TINY_LIB.to_string(),
        patched: tiny_patched.clone(),
        gem: build_gem(
            &stage.join(TINY_GEN2),
            TRANSITIVE,
            "1.0.0",
            "tiny_dep.rb",
            &tiny_patched,
            &[],
        ),
    };
    let server = fx._server.uri();
    let registry = |uuid: &str| format!("{server}/patch-registry/gem/{TOKEN}/{uuid}/");
    let upstream = format!("{server}/upstream/");
    let lock_path = fx.proj.join(fx.lock_name);
    let scan = |what: &str| {
        let (code, stdout, stderr) = run_hosted_scan(&fx.proj, &server);
        assert_eq!(
            code, 0,
            "{what} failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        std::fs::read_to_string(&lock_path).unwrap()
    };

    // Generation 2: both gems hosted, each in its own section, inserted
    // sorted (the path that already worked).
    let tiny_gem = tiny.gem.clone();
    mount_patch_generation(&fx._server, 2, &[vuln(VULN_GEN2, patched_lib()), tiny]).await;
    let lock = scan("generation-2 scan");
    assert_eq!(
        gem_remotes(&lock),
        [registry(VULN_GEN2), registry(TINY_GEN2), upstream.clone()],
        "generation 2 sections:\n{lock}"
    );

    // Generation 3: a superseding patch for vuln-gem only (same version,
    // new bytes) whose uuid sorts after tiny-dep's section.
    let gen3_lib = patched_lib().replace("PATCHED", "PATCHED-GEN3");
    assert_ne!(gen3_lib, patched_lib(), "generation 3 must change bytes");
    let tiny = GenerationGem {
        name: TRANSITIVE,
        uuid: TINY_GEN2,
        deps: vec![],
        lib_file: "tiny_dep.rb",
        orig: TINY_LIB.to_string(),
        patched: tiny_patched,
        gem: tiny_gem,
    };
    mount_patch_generation(&fx._server, 1, &[vuln(VULN_GEN3, gen3_lib), tiny]).await;
    let lock = scan("generation-3 scan");
    assert_eq!(
        gem_remotes(&lock),
        [registry(TINY_GEN2), registry(VULN_GEN3), upstream.clone()],
        "the superseded section must move to bundler's sorted position:\n{lock}"
    );

    // Bundler agrees: `bundle lock` re-renders the committed lock
    // byte-identically, and a cold frozen install accepts it.
    let relock = stage_fresh_checkout(&fx, "fresh-relock");
    let out = bundle(&relock, &["lock"]);
    assert!(
        out.status.success(),
        "bundle lock failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(relock.join(fx.lock_name)).unwrap(),
        lock,
        "bundle lock must leave the converged lock byte-identical"
    );
    let fresh = stage_fresh_checkout(&fx, "fresh-frozen");
    let install = bundle_env(&fresh, &["install"], &[("BUNDLE_FROZEN", "true")]);
    let stderr = String::from_utf8_lossy(&install.stderr);
    assert!(
        install.status.success() && !stderr.contains("Cannot write a changed lockfile"),
        "cold frozen install must accept the lock unchanged.\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&install.stdout),
    );
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

/// #341 follow-through: a CHECKSUMS-converged hosted `gems.rb` pin is a
/// live hosted pin, so `get --mode vendored` takes it over. Vendored mode
/// cannot wire `gems.rb`, and the refusal must come before the takeover
/// reverts the pin.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_gems_rb_pin_survives_a_refused_vendored_takeover() {
    let Some(fx) = redirect_scanned_project(
        "gems.rb takeover",
        Spelling::GemsRb,
        true,
        true,
        None,
        Driver::ScanVex,
    )
    .await
    else {
        return;
    };
    vendor_takeover_keeps_the_hosted_gems_rb_pin(&fx);
}

/// #775: hosted mode accepts a gem declared inside a `group … do` block,
/// but vendored mode refuses an indented declaration. A takeover (`scan`
/// or `get <uuid>` with `--mode vendored`, dry or wet) must raise that
/// refusal BEFORE it restores the hosted pin, or the gem ends up unpatched
/// in both modes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_group_block_pin_survives_a_refused_vendored_takeover() {
    let Some(fx) = redirect_scanned_project(
        "group-block takeover",
        Spelling::Gemfile,
        true,
        true,
        None,
        Driver::ScanVexGroupBlock,
    )
    .await
    else {
        return;
    };
    // The takeover's restore re-derives a CHECKSUMS pin's upstream sha256
    // only for a rubygems.org remote (the shape of the #775 report). Spell
    // the mock upstream as rubygems.org in the pair, and serve that
    // registry from the mock (`SOCKET_RUBYGEMS_URL`, below). No bundler
    // runs after this point.
    let upstream = format!("{}/upstream", fx._server.uri());
    for (file, from, to) in [
        (
            "Gemfile",
            format!("\"{upstream}\""),
            "\"https://rubygems.org\"",
        ),
        (
            "Gemfile.lock",
            format!("{upstream}/"),
            "https://rubygems.org/",
        ),
    ] {
        let path = fx.proj.join(file);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(&from),
            "{file} names the mock upstream:\n{text}"
        );
        std::fs::write(&path, text.replace(&from, to)).unwrap();
    }
    for (command, selector) in [("get", Some(UUID)), ("scan", None)] {
        for dry_run in [true, false] {
            let views = view_requests(&fx).await;
            vendor_takeover_keeps_the_hosted_group_pin(&fx, command, selector, dry_run);
            // The refusal is known before the download phase: a wet scan
            // never fetches the patch view (nor its files) of a gem it
            // cannot vendor. `get <uuid>` fetches the view once to resolve
            // its identifier, and that is all it fetches.
            let fetched = view_requests(&fx).await - views;
            let allowed = usize::from(command == "get");
            assert!(
                fetched <= allowed,
                "{command} --mode vendored (dry_run={dry_run}) fetched the refused gem's \
                 view {fetched} time(s)"
            );
        }
    }
}

/// One refused takeover of the group-block fixture: the
/// `gemfile_declaration_not_editable` refusal (exit 1 wet; a `would_refuse`
/// preview row dry), no revert (nor a preview of one), and the hosted
/// `Gemfile` / `Gemfile.lock` byte-untouched.
fn vendor_takeover_keeps_the_hosted_group_pin(
    fx: &RedirectFixture,
    command: &str,
    selector: Option<&str>,
    dry_run: bool,
) {
    let before: Vec<Vec<u8>> = ["Gemfile", "Gemfile.lock"]
        .iter()
        .map(|f| std::fs::read(fx.proj.join(f)).unwrap())
        .collect();
    let proj = fx.proj.to_str().expect("utf8 tmp path");
    let api = fx._server.uri();
    let mut argv: Vec<&str> = vec![command];
    argv.extend(selector);
    argv.extend([
        "--mode",
        "vendored",
        "--json",
        "--yes",
        "--cwd",
        proj,
        "--api-url",
        &api,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        &api,
    ]);
    if dry_run {
        argv.push("--dry-run");
    }
    let label = format!("{command} --mode vendored (dry_run={dry_run})");
    let upstream = format!("{api}/upstream");
    let (code, stdout, stderr) =
        run_socket_env(&fx.proj, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{label}: not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
    if dry_run {
        // The ledger-classification preview: the refusal is a
        // `would_refuse` row (which never flips the exit code), never
        // `would_vendor`.
        assert_eq!(code, 0, "{label}: {env}");
        let row = &env["vendor"]["patches"][0];
        assert_eq!(row["action"], "would_refuse", "{label}: {env}");
        assert_eq!(
            row["errorCode"], "gemfile_declaration_not_editable",
            "{label}: {env}"
        );
    } else {
        assert_eq!(code, 1, "{label} must refuse: {env}\nstderr:\n{stderr}");
        assert!(
            stdout.contains("gemfile_declaration_not_editable"),
            "{label}: the declaration refusal names its cause: {env}"
        );
    }
    for code in [
        "vendor_takeover_reverted_redirect",
        "vendor_would_revert_redirect",
        "would_vendor",
    ] {
        assert!(
            !stdout.contains(code),
            "{label}: the hosted pin must not be (previewed as) reverted ({code}):\n{stdout}"
        );
    }
    for (file, before) in ["Gemfile", "Gemfile.lock"].iter().zip(before) {
        assert_eq!(
            std::fs::read(fx.proj.join(file)).unwrap(),
            before,
            "{label}: {file} keeps its hosted wiring"
        );
    }
}

/// A hosted→vendored takeover of a `gems.rb` project: vendored mode cannot
/// wire `gems.rb`, so `get --mode vendored` must refuse BEFORE it restores the hosted
/// pin's upstream entry, or the gem ends up unpatched in both modes.
fn vendor_takeover_keeps_the_hosted_gems_rb_pin(fx: &RedirectFixture) {
    let before: Vec<Vec<u8>> = ["gems.rb", "gems.locked"]
        .iter()
        .map(|f| std::fs::read(fx.proj.join(f)).unwrap())
        .collect();
    let proj = fx.proj.to_str().expect("utf8 tmp path");
    let api = fx._server.uri();
    let (code, stdout, stderr) = run_socket(
        &fx.proj,
        &[
            "get",
            UUID,
            "--mode",
            "vendored",
            "--json",
            "--yes",
            "--cwd",
            proj,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
            // The mock serves the patch registry: its origin is the one a
            // hosted pin is trusted on.
            "--patch-server-url",
            &api,
        ],
    );
    assert_ne!(
        code, 0,
        "vendor must refuse.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("gemfile_not_loaded"),
        "the manifest refusal names its cause:\n{stdout}"
    );
    assert!(
        !stdout.contains("vendor_takeover_reverted_redirect"),
        "the hosted pin must not be reverted first:\n{stdout}"
    );
    for (file, before) in ["gems.rb", "gems.locked"].iter().zip(before) {
        assert_eq!(
            std::fs::read(fx.proj.join(file)).unwrap(),
            before,
            "{file} keeps its hosted wiring"
        );
    }
}

/// #390: bundler's `BUNDLE_GEMFILE` (here a committed `.bundle/config`
/// naming `Gemfile.next`, the dual-boot layout) picks the manifest it
/// loads. The hosted scan used to rewrite the ignored `Gemfile`, report
/// success and attest the patch; it must redirect and attest nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_bundle_gemfile_dual_boot_redirects_nothing() {
    let fx = redirect_scanned_project(
        "dual-boot",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexDualBoot,
    )
    .await;
    assert!(fx.is_none(), "the dual-boot driver asserts in place");
}

/// #749: bundler 4's `bundle config set --local lockfile custom.lock`
/// makes bundler read `custom.lock`. The hosted scan used to wire the
/// Gemfile (and the ignored leftover `Gemfile.lock`), report success and
/// attest, while every frozen install then failed; it must redirect and
/// attest nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 4.0 for this arm); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_bundler4_custom_lockfile_redirects_nothing() {
    let fx = redirect_scanned_project(
        "custom-lockfile",
        Spelling::Gemfile,
        true,
        true,
        None,
        Driver::ScanVexCustomLockfile,
    )
    .await;
    assert!(fx.is_none(), "the custom-lockfile driver asserts in place");
}

/// #751: bundler 1.x loads a twin's `Gemfile` and bundler >= 2 its
/// `gems.rb`. The hosted scan used to wire `gems.rb` and attest while
/// bundler 1.17 installed the unpatched gem from the `Gemfile`; since a
/// lock's `BUNDLED WITH` does not say which bundler installs, it must
/// refuse the twin on every bundler line, and the untouched twin must
/// still install.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_twin_redirects_nothing() {
    let fx = redirect_scanned_project(
        "twin",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexTwin,
    )
    .await;
    assert!(fx.is_none(), "the twin driver asserts in place");
}

/// #548: a gem declared in two `group` blocks must not be half-rewritten
/// (bundler refuses `= 1.0.0` next to `>= 0` on every install).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_gem_declared_in_two_groups_is_refused_and_still_installs() {
    let fx = redirect_scanned_project(
        "two-groups",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexDuplicateDeclaration,
    )
    .await;
    assert!(
        fx.is_none(),
        "the duplicate-declaration driver asserts in place"
    );
}

/// #482: a direct dependency declared through `eval_gemfile` must not get a
/// second, appended declaration.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_eval_gemfile_direct_dep_is_refused_and_still_installs() {
    let fx = redirect_scanned_project(
        "eval-gemfile",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexEvalGemfile,
    )
    .await;
    assert!(fx.is_none(), "the eval_gemfile driver asserts in place");
}

/// #652: a gem pulled from a custom `git_source` key must not be "redirected"
/// into a Socket source block the key overrides (bundler would keep loading
/// the unpatched git checkout while VEX attested `not_affected`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_custom_git_source_is_refused_and_still_installs() {
    let fx = redirect_scanned_project(
        "custom-git-source",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexCustomGitSource,
    )
    .await;
    assert!(
        fx.is_none(),
        "the custom git_source driver asserts in place"
    );
}

/// #340: a `gem` declaration that continues on the next line must not be
/// rewritten (the orphaned `require: false` made bundler refuse the Gemfile).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_multi_line_declaration_is_refused_and_still_installs() {
    let fx = redirect_scanned_project(
        "multi-line",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexMultiLineDeclaration,
    )
    .await;
    assert!(fx.is_none(), "the multi-line driver asserts in place");
}

/// #826: `gem "x"; gem "y"` must not be rewritten. The line rewrite
/// deleted `gem "y"`, so the next frozen install failed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            run with a pinned toolchain via --ignored"]
async fn gem_hosted_semicolon_joined_declarations_are_refused_and_still_install() {
    let fx = redirect_scanned_project(
        "semicolon-joined",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexSemicolonJoinedDeclaration,
    )
    .await;
    assert!(fx.is_none(), "the `;`-joined driver asserts in place");
}

/// #826: `gem "x"; # c` is a complete declaration. Since #637 it was
/// refused as continuing on the next line; it must redirect, and a fresh
/// checkout must install the patched bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            run with a pinned toolchain via --ignored"]
async fn gem_hosted_trailing_semicolon_declaration_redirects_and_installs() {
    let Some(fx) = redirect_scanned_project(
        "trailing-semicolon",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexTrailingSemicolonDeclaration,
    )
    .await
    else {
        return;
    };
    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "fresh-checkout `bundle install` must succeed from the patch registry.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_patched_install(&fx, &fresh);
}

/// #340: a `gem` declaration with an `if` modifier must not be rewritten
/// (the rewrite dropped the condition and declared the gem unconditionally).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_conditional_declaration_is_refused_and_still_installs() {
    let fx = redirect_scanned_project(
        "conditional",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexConditionalDeclaration,
    )
    .await;
    assert!(fx.is_none(), "the conditional driver asserts in place");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            run with a pinned toolchain via --ignored"]
async fn gem_hosted_scoped_constant_modifier_is_refused_and_still_installs() {
    let fx = redirect_scanned_project(
        "scoped-constant-modifier",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexScopedConstantModifier,
    )
    .await;
    assert!(fx.is_none(), "the scoped modifier driver asserts in place");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            run with a pinned toolchain via --ignored"]
async fn gem_hosted_heredoc_declaration_is_refused_and_still_installs() {
    for driver in [
        Driver::ScanVexHeredocDeclaration,
        Driver::ScanVexInterpolatedHeredocDeclaration,
    ] {
        let fx =
            redirect_scanned_project(driver.label(), Spelling::Gemfile, false, true, None, driver)
                .await;
        assert!(fx.is_none(), "the heredoc driver asserts in place");
    }
}

/// #507: the same dual boot with `BUNDLE_GEMFILE=Gemfile` exported. Bundler
/// ranks the committed `.bundle/config` above the environment (it still
/// loads `Gemfile.next`), so socket-patch must not follow the env value and
/// wire the `Gemfile` bundler ignores.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_bundle_gemfile_config_outranks_env_redirects_nothing() {
    let fx = redirect_scanned_project(
        "dual-boot-env",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexDualBootEnvGemfile,
    )
    .await;
    assert!(fx.is_none(), "the dual-boot driver asserts in place");
}

/// #681: bundler's `mirror.all` sends the per-dep patch-registry `source`
/// block to the mirror, which serves the upstream gem. The hosted scan used
/// to report the gem redirected and attest it while the next install was
/// unpatched (or failed CHECKSUMS); it must refuse, leave the pair
/// untouched and attest nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_bundler_mirror_all_redirects_nothing() {
    let fx = redirect_scanned_project(
        "mirror-all",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexMirrorAll,
    )
    .await;
    assert!(fx.is_none(), "the mirror.all driver asserts in place");
}

/// Native hostname, exact-source and environment mirrors must refuse before writing or
/// attesting, and credentialed values must stay out of JSON and stderr.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to real ruby/gem/bundler; pinned e2e job runs --ignored"]
async fn gem_hosted_bundler_host_and_environment_mirrors_redirect_nothing() {
    for (label, driver) in [
        ("mirror-host", Driver::ScanVexMirrorHost),
        ("mirror-source", Driver::ScanVexMirrorSource),
        ("mirror-source-env", Driver::ScanVexMirrorSourceEnv),
        ("mirror-all-env", Driver::ScanVexMirrorAllEnv),
    ] {
        let fx =
            redirect_scanned_project(label, Spelling::Gemfile, false, true, None, driver).await;
        assert!(fx.is_none(), "the mirror driver asserts in place");
    }
}

/// A repeat scan can rediscover an older hosted pin even though mirror intake
/// refused it. That pin cannot attest without installed, hash-verified bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to real ruby/gem/bundler; pinned e2e job runs --ignored"]
async fn gem_hosted_mirror_rescan_requires_verified_installed_bytes() {
    let Some(fx) = redirect_scanned_project(
        "mirror-rescan",
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
    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert_patched_install(&fx, &fresh);
    let api = fx._server.uri();
    for (root, installed) in [(&fx.proj, false), (&fresh, true)] {
        let mirror = format!("{api}/upstream/");
        let args = fx.bundler.config_local_args("mirror.127.0.0.1", &mirror);
        let args: Vec<_> = args.iter().map(String::as_str).collect();
        assert!(bundle(root, &args).status.success());
        let gemfile = std::fs::read(root.join(fx.gemfile_name)).unwrap();
        let lock = std::fs::read(root.join(fx.lock_name)).unwrap();
        for no_verify in [false, true] {
            let output = if no_verify {
                "mirror-no-verify.vex.json"
            } else {
                "mirror-verified.vex.json"
            };
            let mut args = vec![
                "scan",
                "--mode",
                "hosted",
                "--json",
                "--yes",
                "--cwd",
                root.to_str().unwrap(),
                "--api-url",
                &api,
                "--patch-server-url",
                &api,
                "--org",
                ORG,
                "--api-token",
                "fake",
                "--vex",
                output,
                "--vex-product",
                PRODUCT,
            ];
            if no_verify {
                args.push("--vex-no-verify");
            }
            let (code, stdout, stderr) = run_socket(root, &args);
            let env: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert!(
                stdout.contains("redirect_gem_mirror_overrides_source"),
                "{env}"
            );
            assert_eq!(env["redirect"]["redirected"], 0, "{env}");
            if installed && !no_verify {
                assert_eq!(code, 0, "{env}\n{stderr}");
                assert_eq!(
                    env["vex"]["statements"], 1,
                    "verified installed bytes remain evidence: {env}"
                );
                assert_patched_install(&fx, root);
            } else {
                assert_ne!(code, 0, "mirror-refused wiring cannot attest: {env}");
                assert!(
                    !root.join(output).exists(),
                    "refused VEX output was written"
                );
                if no_verify {
                    assert!(stdout.contains("mirror_overrides_source"), "{env}");
                }
            }
            assert_eq!(std::fs::read(root.join(fx.gemfile_name)).unwrap(), gemfile);
            assert_eq!(std::fs::read(root.join(fx.lock_name)).unwrap(), lock);
        }
    }
}

/// The compact-index DEPENDENCY contract, pinned from the red side: a patch
/// registry whose `/info` omits the gem's runtime deps (production's
/// HISTORICAL behavior until the 2026-08-18 republish fixed the served index)
/// BREAKS the
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
/// `<name> (= <ver>)!` DEPENDENCIES pin, patched CHECKSUMS sha (v5 keeps no
/// ledger: a rollback re-resolves the upstream sha from the registry). The old mixed-state rewrite (pin only,
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

    // The rewrite half: the registry lock's upstream CHECKSUMS line must
    // actually have been replaced (else the pin is vacuous). No ledger
    // records it (v5).
    let pristine_lock = String::from_utf8_lossy(&fx.pristine_lock).into_owned();
    let original = pristine_lock
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(&format!("{DEP} ({DEP_VERSION}) sha256=")))
        .unwrap_or_else(|| panic!("the registry lock pins an upstream sha:\n{pristine_lock}"))
        .to_string();
    let lock = std::fs::read_to_string(fx.proj.join("Gemfile.lock")).unwrap();
    assert!(
        !lock.contains(&original),
        "the upstream sha line must actually have been replaced (else the pin is vacuous)"
    );
    assert_no_redirect_ledger(&fx.proj);

    // The converged half: GEM section attribution + bundler's own `!` pin.
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

    // UNFROZEN fresh checkout: no exit 37 "mismatched checksums" refusal
    // either.
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
/// exactly one Socket source block, no stale token anywhere, no ledger — and (3) leave a pair a fresh checkout
/// installs the patched bytes from — never wrap the old block's indented
/// gem line in a new NESTED source block (+1 nesting per re-scan) with the
/// stale token URL still live.
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
    let lock_after_run1 = std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap();

    // Re-scan 2, SAME grant: byte-idempotent (Gemfile AND lock), no ledger.
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
        std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap(),
        lock_after_run1,
        "same-grant re-scan must leave the lock byte-identical"
    );
    assert_no_redirect_ledger(&fx.proj);

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
    assert!(
        !gemfile.contains(&fx.index_url),
        "the grant-A index URL must be refreshed away:\n{gemfile}"
    );
    assert_no_redirect_ledger(&fx.proj);

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

/// `scan --mode hosted --json --yes --max-new-patches <cap>`: one capped
/// gradual-rollout run. Returns the parsed envelope.
fn run_capped_hosted_scan(proj: &Path, api: &str, cap: &str) -> serde_json::Value {
    let (code, stdout, stderr) = run_socket(
        proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--max-new-patches",
            cap,
            "--cwd",
            proj.to_str().expect("utf8 tmp path"),
            "--api-url",
            api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    assert_eq!(
        code, 0,
        "capped scan (--max-new-patches {cap}) failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    serde_json::from_str(&stdout).expect("capped scan envelope JSON")
}

/// The rollout counts of a capped scan envelope, as `(new, upgrade,
/// already, deferred)`.
fn rollout_counts(env: &serde_json::Value) -> (u64, u64, u64, u64) {
    let c = &env["rollout"]["counts"];
    let n = |k: &str| c[k].as_u64().unwrap_or_else(|| panic!("counts.{k}: {env}"));
    (n("new"), n("upgrade"), n("already"), n("deferred"))
}

/// #1224: on a lock with no CHECKSUMS section (bundler < 2.6, or an older
/// lock bundler 4 keeps without one) the hosted redirect wires only the
/// Gemfile's `source "<patch registry>" do` block and leaves the lock for
/// the next unfrozen install. A capped re-scan must still count that pin as
/// ALREADY: `--max-new-patches 0` must not defer it, and under a cap of 1
/// the run after the first must spend its slot on the NEXT gem instead of
/// re-counting the wired one as NEW forever.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_capped_rescan_counts_a_gemfile_only_pin_as_already() {
    let Some(fx) = redirect_scanned_project(
        "capped-gemfile-only",
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
    let api = fx._server.uri();
    let lock_path = fx.proj.join(fx.lock_name);
    let gemfile_path = fx.proj.join(fx.gemfile_name);
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        !lock.contains("CHECKSUMS") && !lock.contains(&fx.index_url),
        "the fixture must leave the CHECKSUMS-less lock mixed (Gemfile-only pin):\n{lock}"
    );

    // Single gem, already wired in the Gemfile: "upgrade existing patches
    // only" must read it as ALREADY, not defer it as NEW.
    let env = run_capped_hosted_scan(&fx.proj, &api, "0");
    assert_eq!(rollout_counts(&env), (0, 0, 1, 0), "cap 0 re-scan: {env}");
    let deferred = env["skipped"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|s| s["reason"] == "rollout_deferred");
    assert!(!deferred, "a wired gem must not be rollout_deferred: {env}");

    // Two patchable gems under a cap of 1, from the pristine pair: run 1
    // wires one, run 2 must wire the other, run 3 finds both in place.
    const TINY_GEN2: &str = "80000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let stage = fx.tmp.path().join("generation-stage");
    let vuln = GenerationGem {
        name: DEP,
        uuid: UUID,
        deps: vec![format!("{TRANSITIVE}:>= 0")],
        lib_file: "vuln_gem.rb",
        orig: orig_lib(),
        patched: patched_lib(),
        gem: build_gem(
            &stage.join("vuln"),
            DEP,
            DEP_VERSION,
            "vuln_gem.rb",
            &patched_lib(),
            &[TRANSITIVE],
        ),
    };
    let tiny_patched = TINY_LIB.replace("tiny-ok", "tiny-patched");
    let tiny = GenerationGem {
        name: TRANSITIVE,
        uuid: TINY_GEN2,
        deps: vec![],
        lib_file: "tiny_dep.rb",
        orig: TINY_LIB.to_string(),
        patched: tiny_patched.clone(),
        gem: build_gem(
            &stage.join("tiny"),
            TRANSITIVE,
            "1.0.0",
            "tiny_dep.rb",
            &tiny_patched,
            &[],
        ),
    };
    mount_patch_generation(&fx._server, 1, &[vuln, tiny]).await;
    std::fs::write(&gemfile_path, &fx.pristine_gemfile).unwrap();
    std::fs::write(&lock_path, &fx.pristine_lock).unwrap();
    let registry = |uuid: &str| format!("{api}/patch-registry/gem/{TOKEN}/{uuid}/");

    let env = run_capped_hosted_scan(&fx.proj, &api, "1");
    assert_eq!(rollout_counts(&env), (1, 0, 0, 1), "run 1: {env}");
    let env = run_capped_hosted_scan(&fx.proj, &api, "1");
    assert_eq!(
        rollout_counts(&env),
        (1, 0, 1, 0),
        "run 2 must count the gem run 1 wired as ALREADY and add the other: {env}"
    );
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    for (gem, patch) in [(DEP, UUID), (TRANSITIVE, TINY_GEN2)] {
        assert!(
            gemfile.contains(&registry(patch)),
            "run 2 must leave both gems wired ({gem} missing)"
        );
    }
    let env = run_capped_hosted_scan(&fx.proj, &api, "1");
    assert_eq!(rollout_counts(&env), (0, 0, 2, 0), "run 3: {env}");
    assert_eq!(
        std::fs::read_to_string(&gemfile_path).unwrap(),
        gemfile,
        "run 3 must leave the Gemfile byte-identical"
    );
}

/// #1224 (superseding shape): a newer patch for the same gem version, new
/// uuid, over a Gemfile-only pin. `--max-new-patches 0` ("upgrade existing
/// patches only") must see the recorded pin and UPGRADE it to the new uuid,
/// as it does on a CHECKSUMS lock, instead of deferring it as NEW and
/// leaving the Gemfile on the superseded patch.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_cap_zero_upgrades_a_superseded_gemfile_only_pin() {
    let Some(fx) = redirect_scanned_project(
        "cap-zero-supersede",
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
    let api = fx._server.uri();
    const VULN_GEN2: &str = "10000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let gen2_lib = patched_lib().replace("PATCHED", "PATCHED-GEN2");
    let stage = fx.tmp.path().join("generation-stage");
    let vuln = GenerationGem {
        name: DEP,
        uuid: VULN_GEN2,
        deps: vec![format!("{TRANSITIVE}:>= 0")],
        lib_file: "vuln_gem.rb",
        orig: orig_lib(),
        patched: gen2_lib.clone(),
        gem: build_gem(
            &stage.join(VULN_GEN2),
            DEP,
            DEP_VERSION,
            "vuln_gem.rb",
            &gen2_lib,
            &[TRANSITIVE],
        ),
    };
    mount_patch_generation(&fx._server, 1, &[vuln]).await;

    let env = run_capped_hosted_scan(&fx.proj, &api, "0");
    assert_eq!(rollout_counts(&env), (0, 1, 0, 0), "cap 0 re-scan: {env}");
    let gemfile = std::fs::read_to_string(fx.proj.join(fx.gemfile_name)).unwrap();
    assert!(
        gemfile.contains(&format!("{api}/patch-registry/gem/{TOKEN}/{VULN_GEN2}/"))
            && !gemfile.contains(&fx.index_url),
        "the Gemfile must move to the superseding patch:\n{gemfile}"
    );
}
