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
//!   2. `scan --mode hosted --json --vex …` (the real binary): the gem's own
//!      declaration in the Gemfile gains a `source: "<index-url>"` option
//!      (nothing else of it changes) and the lock is converged to what the
//!      host bundler itself writes for that Gemfile — asserted by running
//!      the real `bundle lock` over the pre-scan lock and comparing bytes —
//!      on every lock era: a `GEM` section of its own on bundler >= 2.2
//!      (with the patched sha256 where the lock has `CHECKSUMS`), one more
//!      `remote:` in the single section on bundler < 2.2. NO redirect ledger
//!      is written (v5: the manifest pair is the hosted state), the in-run
//!      VEX is the unverified `(redirected)` attestation.
//!   3. FRESH-CHECKOUT PROOF: only the committable files travel; a FROZEN
//!      `bundle install` (what CI and deploys run) resolves the patched gem
//!      from the mock patch registry and leaves the lock byte-identical:
//!      installed bytes byte-match the patch blob, the runtime dep installs
//!      BECAUSE the registry `/info` declares it, and a require probe loads
//!      the patched code.
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
//! Every lock comes out FULLY CONVERGED, with or without a `CHECKSUMS`
//! section: the DEPENDENCIES entry keeps the requirement the user declared
//! and gains the `!`, and where the lock has `CHECKSUMS` the entry holds the
//! patched sha. The canary proves the converged pair installs patched bytes
//! on a fresh checkout both FROZEN (`BUNDLE_FROZEN=true`, lock
//! byte-identical) and unfrozen. The Socket backend's TS twin of this
//! rewriter must be ported to match.
//!
//! `rollback` / `remove` take the option off again: the pair is the
//! pre-scan pair, byte for byte.
//!
//! A pin socket-patch 5.0 / 5.1 wrote (a `source "<index-url>" do … end`
//! block in the declaration's place) is built by hand over the fixture and
//! locked by the real bundler: a re-scan leaves it alone, `vex` attests it,
//! and its unwind brings the declaration back as the exact pin and says so.
//!
//! The grant-rotation capstone drives token A -> A -> B re-scans through the
//! real binary: byte-idempotent under the same grant, in-place URL refresh
//! (the Gemfile option + the converged lock's remote) under a rotated one.
//!
//! MANIFEST-LESS VEX (every installing arm, `manifestless_vex_matrix`): on
//! the fresh checkout the real bundler installed — hosted never writes a
//! `.socket/manifest.json` nor a ledger — `vex` attests `(redirected)` from
//! the lockfile wiring + the patch API (and so does the embedded
//! `apply --vex`); `--offline` is `record_unavailable` with zero requests;
//! the pair reverted to its registry version names the patch nowhere, even
//! under `--no-verify`. The main arm also proves the lock-only revert
//! (the Gemfile's option kept) re-converges on the next unfrozen install,
//! and on the next hosted scan.
//!
//! PLATFORM GEMS (the cases at the end of the file, on a lock the real
//! bundler wrote for a gem published as precompiled platform gems): the
//! gem's fix is one patch, whose reference lists every platform gem of the
//! version under a registry snapshot. Every locked build moves to that
//! registry once one of them is patched. A machine of a patched platform
//! installs the patched gem; a machine of a platform with no patched build
//! yet installs upstream's gem, which the registry answers with a redirect
//! to the upstream registry's file (here a second wiremock). The cases:
//! every locked build patched (with and without `CHECKSUMS`, with the ruby
//! entry beside the builds, and taken over by a vendored run), one build
//! patched (this machine in either role), none patched or one still being
//! made (nothing moves, quietly), a newer snapshot, `bundle lock
//! --add-platform` over a hosted lock, and a refresh whose download the
//! registry redirects.
//!
//! VERSION MATRIX: the arms run on bundler 1.17 → 4.x (the CHECKSUMS arm
//! from 2.6, the CHECKSUMS-era floor; every other arm from 1.17). Pick the
//! bundler with `PATH` (CI: `ruby/setup-ruby`'s `bundler:` input) and name
//! it in `SOCKET_PATCH_BUNDLER_E2E_VERSION` (asserted) plus
//! `SOCKET_PATCH_BUNDLER_E2E_REQUIRED=1` (missing toolchain = failure) —
//! see `common/bundler_e2e.rs`. Lock shapes per era, each written by the
//! scan itself: for bundler 1.17–2.1 ONE merged `GEM` section listing both
//! remotes (attributed through the Gemfile's `source:` option), from 2.2 on
//! a separate patch-registry section; before 2.2 there is no API-mismatch
//! check (the deps red-arm's signature differs).
//!
//! Skips (with a println) when `ruby`/`gem`/`bundle` are missing (a hard
//! failure under `SOCKET_PATCH_BUNDLER_E2E_REQUIRED=1`) or the bundler is
//! below the arm's floor; everything after that is hard — no live network is
//! involved at all.

#[path = "common/mod.rs"]
mod common;
use common::{binary, hermetic, hermetic_command};

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/bundler_e2e.rs"]
mod bundler_e2e;
use common::cache_env;
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

/// The gem library a [`Driver::ScanVexGemspecDevDependency`] project
/// builds: its gemspec declares the vulnerable gem as a development
/// dependency.
const GEMSPEC_LIB: &str = "mylib.gemspec";

fn gemspec_lib() -> String {
    format!(
        "Gem::Specification.new do |s|\n  s.name = \"mylib\"\n  s.version = \"0.1.0\"\n  \
         s.summary = \"x\"\n  s.authors = [\"x\"]\n  s.files = [\"lib/mylib.rb\"]\n  \
         s.add_development_dependency \"{DEP}\"\nend\n"
    )
}

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

/// Run the socket-patch binary in the hermetic environment
/// (`tests/common/hermetic.rs`: a developer's `SOCKET_DRY_RUN=1` must not
/// steer the assertions) with the crawler's discovery inputs scrubbed
/// (`hermetic::scrub_crawler_inputs`: `VIRTUAL_ENV`, every `BUNDLE_*` the
/// crawler reads, and `~/.bundle/config` via a pinned `BUNDLE_USER_CONFIG`).
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    run_socket_env(cwd, args, &[])
}

/// [`run_socket`] with extra environment on top of the scrubbed surface.
fn run_socket_env(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    hermetic::scrub_crawler_inputs(&mut cmd);
    cmd.args(args).current_dir(cwd);
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

/// Run `bundle <args>` in `cwd`: ambient `SOCKET_*` and bundler config
/// scrubbed ([`hermetic::Extra::Bundle`]; `GEM_HOME`/`GEM_PATH` stay, see
/// `cache_env.rs`, and every install here uses the project-local `path`
/// config), caches isolated, `BUNDLE_APP_CONFIG` pinned to the project's own `.bundle/`, and
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
    hermetic::scrub_socket_vars(&mut cmd);
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Bundle]);
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

/// `manifest` as hosted mode leaves it: `, source: "<index_url>"` right
/// after `last_argument` (the text the gem's declaration ends its argument
/// list with), every other byte as it was.
fn with_source_option(manifest: &str, last_argument: &str, index_url: &str) -> String {
    let at = manifest
        .find(last_argument)
        .unwrap_or_else(|| panic!("{last_argument:?} is not in the manifest:\n{manifest}"))
        + last_argument.len();
    format!(
        "{}, source: \"{index_url}\"{}",
        &manifest[..at],
        &manifest[at..]
    )
}

/// `manifest` as socket-patch 5.0 / 5.1 left it: the `gem "<DEP>"…`
/// declaration line replaced by a `source "<index_url>" do … end` block
/// that declares the exact version. That rewriter matched `^\s*gem`, so the
/// blank lines and the indent before the declaration went with it.
fn with_source_block(manifest: &str, index_url: &str) -> String {
    let decl = manifest
        .find(&format!("gem \"{DEP}\""))
        .unwrap_or_else(|| panic!("no `gem \"{DEP}\"` declaration:\n{manifest}"));
    let start = match manifest[..decl].trim_end().len() {
        0 => 0,
        text_end => text_end + 1,
    };
    let line_end = manifest[decl..]
        .find('\n')
        .map_or(manifest.len(), |i| decl + i);
    format!(
        "{}source \"{index_url}\" do\n  gem \"{DEP}\", \"{DEP_VERSION}\"\nend{}",
        &manifest[..start],
        &manifest[line_end..]
    )
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
    /// blocks (#548): bundler accepts the duplicate, but giving only one
    /// declaration the Socket source would leave the gem with two sources.
    /// The run must refuse, write nothing and attest nothing; the fixture
    /// asserts that and yields `None`.
    ScanVexDuplicateDeclaration,
    /// [`Driver::ScanVex`] on a Gemfile that declares the gem through
    /// `eval_gemfile` (#482): the lock lists it as a direct dependency, so
    /// adding a line for it would declare it twice. Same contract as
    /// [`Driver::ScanVexDuplicateDeclaration`].
    ScanVexEvalGemfile,
    /// [`Driver::ScanVex`] on a Gemfile whose declaration continues on the
    /// next line (`gem "x",` ↵ `require: false`, #340): the option goes
    /// after the last argument, on the continuation line.
    ScanVexMultiLineDeclaration,
    /// [`Driver::ScanVex`] on a Gemfile whose declaration carries an `if`
    /// modifier (#340): the option goes before the modifier, which stays.
    ScanVexConditionalDeclaration,
    /// A modifier adjacent to a top-level constant is still a modifier,
    /// not a hash label (`if::ENV`, #340): the option goes before it.
    ScanVexScopedConstantModifier,
    /// [`Driver::ScanVex`] on a gem declared inside the user's own
    /// `source "<upstream>" do` block (#1056): the block already selects
    /// the gem's source (bundler locks it with a `!` source pin), so the
    /// run refuses it. Same contract as
    /// [`Driver::ScanVexDuplicateDeclaration`].
    ScanVexSourceBlock,
    /// [`Driver::ScanVexSourceBlock`] with assignment-form keyword
    /// constructs (`v = if … end`, `w = case … end`) before the gem
    /// (#1476): their `end`s must not close the user's source block.
    ScanVexSourceBlockAssignment,
    /// [`Driver::ScanVexSourceBlock`] whose `source(` opener spans lines
    /// before its `do` (#1509).
    ScanVexSourceBlockMultiLineOpener,
    /// [`Driver::ScanVexSourceBlock`] as a `source(…) { … }` brace block
    /// (#1509): bundler pins it with `!` too.
    ScanVexSourceBlockBraces,
    /// [`Driver::ScanVexSourceBlock`] whose `source … do` follows another
    /// statement and a `;` on its line (#1531).
    ScanVexSourceBlockAfterSemicolon,
    /// [`Driver::ScanVex`] on a Gemfile with a second top-level `source`
    /// line (#2162). Bundler 2.2 to 2.7 lock such a Gemfile into ONE `GEM`
    /// section naming both remotes, which `bundle lock` writes again as it
    /// is: the run refuses the gem, names the Gemfile's sources as the
    /// cause, and the remedy it prescribes (the second source in a block,
    /// `bundle lock`) makes the next scan wire the gem.
    ScanVexTwoGlobalSources,
    /// A heredoc option continues beyond the declaration's physical line.
    ScanVexHeredocDeclaration,
    /// A double-quoted interpolation can itself contain a heredoc opener.
    ScanVexInterpolatedHeredocDeclaration,
    /// A second declaration joined to the gem's line by `;` (#826): it
    /// stays where it is, the option going before the `;`.
    ScanVexSemicolonJoinedDeclaration,
    /// [`Driver::ScanVex`] on a declaration ending in a bare `;` and a
    /// comment (#826): a complete declaration, so it is redirected.
    ScanVexTrailingSemicolonDeclaration,
    /// [`Driver::ScanVex`] on a gem library whose Gemfile's `gemspec`
    /// directive also declares the gem as a development dependency (#985):
    /// bundler 2.7+ merges the two requirements, and the lock must keep the
    /// requirement bundler recorded for frozen installs to accept it.
    ScanVexGemspecDevDependency,
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
    /// [`Driver::ScanVexCustomLockfile`] with the lock named by a
    /// `lockfile "custom.lock"` call at the top of the Gemfile instead of
    /// the config (#1477): bundler 4's DSL spelling, which outranks every
    /// `BUNDLE_LOCKFILE` tier. Bundler >= 4 only.
    ScanVexCustomLockfileDsl,
    /// [`Driver::ScanVex`] on a `Gemfile` + `gems.rb` twin (#751): bundler
    /// 1.x loads the `Gemfile` and >= 2 loads `gems.rb`, and the scan cannot
    /// see which runs, so it must redirect and attest nothing and leave all
    /// four files byte-identical. Every bundler line.
    ScanVexTwin,
    /// [`Driver::ScanVex`] on a Gemfile that declares the gem inside a
    /// `group :development do … end` block (#775): hosted mode edits the
    /// declaration where it is, but vendored mode cannot edit an indented
    /// declaration, so a later takeover must refuse before it un-hosts the
    /// gem.
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
    /// `git_source(:local)` key (#652): the key selects the gem's one
    /// source, and bundler keeps loading the unpatched git checkout. Same
    /// refuse-and-attest-nothing contract as
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
            Driver::ScanVexCustomLockfileDsl => {
                "scan --mode hosted (Gemfile `lockfile \"custom.lock\"` call)"
            }
            Driver::ScanVexTwin => "scan --mode hosted (Gemfile + gems.rb twin)",
            Driver::ScanVexGroupBlock => "scan --mode hosted (gem in a group block)",
            Driver::ScanVexSourceBlock => "scan --mode hosted (gem in a source block)",
            Driver::ScanVexTwoGlobalSources => {
                "scan --mode hosted (Gemfile with two top-level sources)"
            }
            Driver::ScanVexSourceBlockAssignment => {
                "scan --mode hosted (gem in a source block after `v = if … end`)"
            }
            Driver::ScanVexSourceBlockMultiLineOpener => {
                "scan --mode hosted (gem in a multi-line `source(…) do` block)"
            }
            Driver::ScanVexSourceBlockBraces => {
                "scan --mode hosted (gem in a `source(…) { }` block)"
            }
            Driver::ScanVexSourceBlockAfterSemicolon => {
                "scan --mode hosted (gem in a `x = 1; source … do` block)"
            }
            Driver::ScanVexSemicolonJoinedDeclaration => {
                "scan --mode hosted (two `;`-joined gem declarations)"
            }
            Driver::ScanVexTrailingSemicolonDeclaration => {
                "scan --mode hosted (gem line ending in `;`)"
            }
            Driver::ScanVexGemspecDevDependency => {
                "scan --mode hosted (gem also a gemspec development dependency)"
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
        Driver::ScanVexCustomLockfile | Driver::ScanVexCustomLockfileDsl
            if !bundler.at_least(4, 0) =>
        {
            Some("custom lockfiles need bundler >= 4")
        }
        // Before 2.2 the lock is the merged layout anyway; bundler 4
        // refuses the Gemfile.
        Driver::ScanVexTwoGlobalSources if !bundler.at_least(2, 2) || bundler.at_least(4, 0) => {
            Some("a Gemfile with two top-level sources is locked into one multi-remote GEM section by bundler 2.2 to 2.7 only")
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
        Driver::ScanVexSourceBlock => format!(
            "source \"{up}/upstream\"\n\nsource \"{up}/upstream\" do\n  gem \"{DEP}\", \"{DEP_VERSION}\"\nend\n",
            up = server.uri()
        ),
        Driver::ScanVexTwoGlobalSources => {
            // A second gem server with a gem of its own, as a private
            // server beside rubygems.org has.
            let gem = build_gem(
                &stage,
                SECOND_SOURCE_GEM,
                "1.0.0",
                "second_only.rb",
                TINY_LIB,
                &[],
            );
            let second = IndexGem {
                name: SECOND_SOURCE_GEM,
                version: "1.0.0",
                deps: vec![],
                gem,
            };
            mount_compact_index(&server, "/second", &[second]).await;
            format!(
                "source \"{up}/upstream\"\nsource \"{up}/second\"\n\ngem \"{DEP}\"\n\
                 gem \"{SECOND_SOURCE_GEM}\"\n",
                up = server.uri()
            )
        }
        Driver::ScanVexSourceBlockAssignment => format!(
            "source \"{up}/upstream\"\n\nsource \"{up}/upstream\" do\n  v = if ENV[\"ZZ\"]\n    \"a\"\n  \
             else\n    \"b\"\n  end\n  w = case ENV[\"ZZ\"]\n      when \"x\" then \"a\"\n      \
             else \"b\"\n      end\n  gem \"{DEP}\", \"{DEP_VERSION}\"\nend\n",
            up = server.uri()
        ),
        Driver::ScanVexSourceBlockMultiLineOpener => format!(
            "source \"{up}/upstream\"\n\nsource(\n  \"{up}/upstream\"\n) do\n  \
             gem \"{DEP}\", \"{DEP_VERSION}\"\nend\n",
            up = server.uri()
        ),
        Driver::ScanVexSourceBlockBraces => format!(
            "source \"{up}/upstream\"\n\nsource(\"{up}/upstream\") {{\n  \
             gem \"{DEP}\", \"{DEP_VERSION}\"\n}}\n",
            up = server.uri()
        ),
        Driver::ScanVexSourceBlockAfterSemicolon => format!(
            "source \"{up}/upstream\"\n\nzz = 1; source \"{up}/upstream\" do\n  \
             gem \"{DEP}\", \"{DEP_VERSION}\"\nend\n",
            up = server.uri()
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
            // section, never from the registry a Socket `source:` names.
            let repos = tmp.path().join("repos");
            let repo = repos.join(DEP);
            copy_dir_recursive(&stage.join(format!("{DEP}-src")), &repo);
            for args in [
                &["init", "-q"][..],
                // Bundler <= 2.1 checks out `master` when the Gemfile names
                // no ref, whatever `init.defaultBranch` says.
                &["symbolic-ref", "HEAD", "refs/heads/master"][..],
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
        Driver::ScanVexGemspecDevDependency => {
            std::fs::create_dir_all(proj.join("lib")).unwrap();
            std::fs::write(proj.join("lib/mylib.rb"), "module Mylib; end\n").unwrap();
            std::fs::write(proj.join(GEMSPEC_LIB), gemspec_lib()).unwrap();
            format!(
                "source \"{}/upstream\"\n\ngemspec\n\ngem \"{DEP}\"\n",
                server.uri()
            )
        }
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
    let mut pristine_gemfile = std::fs::read(proj.join(gemfile_name)).unwrap();
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
    let custom_lockfile_dsl = driver == Driver::ScanVexCustomLockfileDsl;
    if custom_lockfile_dsl {
        // The Gemfile's own `lockfile "custom.lock"` call, as a bundler 4
        // project writes it; the default lock stays behind as a leftover.
        std::fs::copy(proj.join(lock_name), proj.join("custom.lock")).unwrap();
        let mut gemfile = b"lockfile \"custom.lock\"\n".to_vec();
        gemfile.extend_from_slice(&pristine_gemfile);
        std::fs::write(proj.join(gemfile_name), &gemfile).unwrap();
        pristine_gemfile = gemfile;
    }
    let custom_lockfile = driver == Driver::ScanVexCustomLockfile || custom_lockfile_dsl;
    if driver == Driver::ScanVexCustomLockfile {
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
        | Driver::ScanVexCustomLockfileDsl
        | Driver::ScanVexTwin
        | Driver::ScanVexDualBoot
        | Driver::ScanVexDualBootEnvGemfile
        | Driver::ScanVexDuplicateDeclaration
        | Driver::ScanVexEvalGemfile
        | Driver::ScanVexGroupBlock
        | Driver::ScanVexSourceBlock
        | Driver::ScanVexTwoGlobalSources
        | Driver::ScanVexSourceBlockAssignment
        | Driver::ScanVexSourceBlockMultiLineOpener
        | Driver::ScanVexSourceBlockBraces
        | Driver::ScanVexSourceBlockAfterSemicolon
        | Driver::ScanVexCustomGitSource
        | Driver::ScanVexMultiLineDeclaration
        | Driver::ScanVexConditionalDeclaration
        | Driver::ScanVexScopedConstantModifier
        | Driver::ScanVexHeredocDeclaration
        | Driver::ScanVexInterpolatedHeredocDeclaration
        | Driver::ScanVexSemicolonJoinedDeclaration
        | Driver::ScanVexTrailingSemicolonDeclaration
        | Driver::ScanVexGemspecDevDependency => vec![
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
        Driver::ScanVexCustomGitSource
        | Driver::ScanVexSourceBlock
        | Driver::ScanVexSourceBlockAssignment
        | Driver::ScanVexSourceBlockMultiLineOpener
        | Driver::ScanVexSourceBlockBraces
        | Driver::ScanVexSourceBlockAfterSemicolon => Some("redirect_gem_source_option"),
        Driver::ScanVexTwoGlobalSources => Some("redirect_gem_lock_unconvergeable"),
        Driver::ScanVexHeredocDeclaration | Driver::ScanVexInterpolatedHeredocDeclaration => {
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
        if driver == Driver::ScanVexTwoGlobalSources {
            assert_two_global_sources_remedy_wires(&proj, &api, &index_url, &lock_before, &stdout);
        }
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
        env["summary"]["applied"], 1,
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
    // `warnings` is omitted when the run has none.
    let warning_codes: Vec<&str> = env["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| w["code"].as_str())
        .collect();
    // Every lock converges with the Gemfile (a patch-registry GEM section
    // or, before bundler 2.2, remote; the `!` on the dependency; the patched
    // sha where the lock holds checksums), so the pair is frozen-installable
    // as written and there is no frozen-install caveat to give.
    assert!(
        !warning_codes.contains(&"redirect_gem_frozen_install"),
        "a converged pair must not carry the frozen-install caveat: {env}"
    );
    assert!(
        rewritten.contains(&lock_name),
        "{lock_name} must follow the {gemfile_name}: {env}"
    );
    // The one thing a lock without CHECKSUMS cannot hold is said, once.
    assert_eq!(
        warning_codes
            .iter()
            .filter(|code| **code == "redirect_gem_no_checksums_section")
            .count(),
        usize::from(!checksums_lock),
        "a lock that cannot record the artifact checksum must say so once: {env}"
    );
    // The pair is converged for the bundler that wrote the lock. Only the
    // one merged section of bundler < 2.2 is a layout later bundlers turn
    // down, so only there does the run name the bundler the pair is for.
    assert_eq!(
        warning_codes.contains(&"redirect_gem_merged_lock_layout"),
        !bundler.at_least(2, 2),
        "a merged lock (bundler < 2.2) names the bundler it is converged for: {env}"
    );
    match driver {
        Driver::ScanVex
        | Driver::ScanVexGroupBlock
        | Driver::ScanVexMultiLineDeclaration
        | Driver::ScanVexConditionalDeclaration
        | Driver::ScanVexScopedConstantModifier
        | Driver::ScanVexSemicolonJoinedDeclaration
        | Driver::ScanVexTrailingSemicolonDeclaration
        | Driver::ScanVexGemspecDevDependency => {
            assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
            assert!(
                env["vex"]["warnings"]
                    .as_array()
                    .is_some_and(|w| w.iter().any(|w| w["code"] == "vex_hosted_unverified")),
                "in-run hosted VEX is attested from this run's fetched record, not hash-verified: {env}"
            );
        }
        Driver::ScanVexDualBoot
        | Driver::ScanVexDualBootEnvGemfile
        | Driver::ScanVexCustomLockfile
        | Driver::ScanVexCustomLockfileDsl
        | Driver::ScanVexTwin
        | Driver::ScanVexDuplicateDeclaration
        | Driver::ScanVexEvalGemfile
        | Driver::ScanVexMirrorAll
        | Driver::ScanVexMirrorHost
        | Driver::ScanVexMirrorSource
        | Driver::ScanVexMirrorSourceEnv
        | Driver::ScanVexMirrorAllEnv
        | Driver::ScanVexCustomGitSource
        | Driver::ScanVexSourceBlock
        | Driver::ScanVexTwoGlobalSources
        | Driver::ScanVexSourceBlockAssignment
        | Driver::ScanVexSourceBlockMultiLineOpener
        | Driver::ScanVexSourceBlockBraces
        | Driver::ScanVexSourceBlockAfterSemicolon
        | Driver::ScanVexHeredocDeclaration
        | Driver::ScanVexInterpolatedHeredocDeclaration => {
            unreachable!("asserted and returned above")
        }
        Driver::GetUuid => {
            // get's hosted envelope: the resolved patch's hosted pin is its
            // one event; nothing is downloaded into `.socket/` (the
            // lockfile IS the persistence) and no `vex` key (get has no
            // --vex).
            assert_eq!(
                env["events"].as_array().map(Vec::len),
                Some(1),
                "envelope: {env}"
            );
            assert_eq!(
                env["summary"]["downloaded"], 0,
                "hosted get downloads nothing into .socket/: {env}"
            );
            assert!(env.get("vex").is_none(), "get has no --vex: {env}");
        }
    }

    // The Gemfile edit: the user's declaration, byte for byte, with ONE
    // option after its last argument — the patch-registry compact index as
    // the gem's source. Nothing else in the file changes.
    let gemfile = std::fs::read_to_string(proj.join(gemfile_name)).unwrap();
    let pristine = String::from_utf8(pristine_gemfile.clone()).expect("utf8 Gemfile");
    let last_argument = match driver {
        Driver::ScanVexMultiLineDeclaration => "require: false".to_string(),
        Driver::ScanVexScopedConstantModifier | Driver::ScanVexSemicolonJoinedDeclaration => {
            format!("gem \"{DEP}\", \"{DEP_VERSION}\"")
        }
        _ => format!("gem \"{DEP}\""),
    };
    assert_eq!(
        gemfile,
        with_source_option(&pristine, &last_argument, &index_url),
        "{gemfile_name} must keep the declaration and gain the `source:` option"
    );
    let lock = std::fs::read_to_string(proj.join(lock_name)).unwrap();
    if checksums_lock {
        assert!(
            lock.contains(&format!("  {DEP} ({DEP_VERSION}) sha256={patched_sha}")),
            "the lock CHECKSUMS must pin the PATCHED .gem's sha256:\n{lock}"
        );
    }
    // The lock is the one the host bundler writes for that Gemfile over the
    // pre-scan lock, byte for byte — so a frozen install accepts it, on
    // every bundler line (one merged GEM section before 2.2, a section per
    // source after). The deps red-arm has no such reference: its registry
    // misreports the gem's dependencies, so bundler's own resolution over
    // it drops the runtime dependency the scan (rightly) keeps.
    if registry_declares_deps {
        let relock = tmp.path().join("relock");
        std::fs::create_dir_all(&relock).unwrap();
        std::fs::write(relock.join(gemfile_name), &gemfile).unwrap();
        std::fs::write(relock.join(lock_name), &pristine_lock).unwrap();
        for extra in [GEMSPEC_LIB, "lib"] {
            let from = proj.join(extra);
            if from.is_dir() {
                copy_dir_recursive(&from, &relock.join(extra));
            } else if from.is_file() {
                std::fs::copy(&from, relock.join(extra)).unwrap();
            }
        }
        copy_dir_recursive(&proj.join(".bundle"), &relock.join(".bundle"));
        let out = bundle(&relock, &["lock"]);
        assert!(
            out.status.success(),
            "bundle lock over the redirected {gemfile_name} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            lock,
            std::fs::read_to_string(relock.join(lock_name)).unwrap(),
            "the scan's {lock_name} must be what bundler {} writes for the redirected {gemfile_name}",
            bundler.version
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

/// The gem only the second source of [`Driver::ScanVexTwoGlobalSources`]
/// serves.
const SECOND_SOURCE_GEM: &str = "second_only";

/// #2162, after the refused scan of [`Driver::ScanVexTwoGlobalSources`]:
/// the fixture lock is the one multi-remote `GEM` section the report is
/// about and `bundle lock` leaves it alone; the warning names the Gemfile's
/// top-level sources and the block remedy, never an old bundler or
/// vendored mode; and that remedy works: with the second source in a
/// block, `bundle lock` gives each source a section, the next scan wires
/// the gem, and bundler installs the pair frozen.
fn assert_two_global_sources_remedy_wires(
    proj: &Path,
    api: &str,
    index_url: &str,
    lock_before: &str,
    refused_stdout: &str,
) {
    assert_eq!(gem_remotes(lock_before).len(), 2, "{lock_before}");
    assert_eq!(
        lock_before.matches("GEM\n").count(),
        1,
        "one GEM section names both remotes:\n{lock_before}"
    );
    let relock = bundle(proj, &["lock"]);
    assert!(relock.status.success(), "bundle lock failed");
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
        lock_before,
        "`bundle lock` leaves the two-remote lock as it is"
    );
    for said in [
        "Gemfile has 2 top-level `source` lines",
        "do … end` block",
        "--mode agent",
    ] {
        assert!(
            refused_stdout.contains(said),
            "the warning says {said:?}:\n{refused_stdout}"
        );
    }
    for unsaid in ["bundler < 2.2", "--mode vendored"] {
        assert!(
            !refused_stdout.contains(unsaid),
            "the warning must not say {unsaid:?}:\n{refused_stdout}"
        );
    }

    // The remedy the warning names.
    let gemfile = std::fs::read_to_string(proj.join("Gemfile")).unwrap();
    let second = gemfile
        .lines()
        .nth(1)
        .filter(|line| line.starts_with("source \"") && line.ends_with("/second\""))
        .unwrap_or_else(|| panic!("the second top-level source: {gemfile}"));
    let own_gem = format!("gem \"{SECOND_SOURCE_GEM}\"\n");
    assert!(gemfile.ends_with(&own_gem), "{gemfile}");
    let remedied = format!(
        "{}\n{second} do\n  {own_gem}end\n",
        gemfile
            .replacen(&format!("{second}\n"), "", 1)
            .replacen(&own_gem, "", 1)
    );
    std::fs::write(proj.join("Gemfile"), &remedied).unwrap();
    let relock = bundle(proj, &["lock"]);
    assert!(
        relock.status.success(),
        "bundle lock over the remedied Gemfile failed:\n{}",
        String::from_utf8_lossy(&relock.stderr)
    );
    // The install the helper above ran is stale for the scan to come.
    std::fs::remove_dir_all(proj.join("vendor")).expect("remove the materialization");
    let (code, stdout, stderr) = run_hosted_scan(proj, api);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        !stdout.contains("redirect_gem_lock_unconvergeable"),
        "the remedied project is wired:\n{stdout}"
    );
    let wired = std::fs::read_to_string(proj.join("Gemfile")).unwrap();
    assert_eq!(
        wired,
        with_source_option(&remedied, &format!("gem \"{DEP}\""), index_url),
        "the declaration gains the `source:` option"
    );
    let lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
    assert!(
        gem_remotes(&lock).contains(&index_url),
        "the lock records the patch source:\n{lock}"
    );
    let install = bundle_env(proj, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        install.status.success(),
        "a frozen install must accept the wired pair:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
        lock,
        "the frozen install leaves the lock alone"
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
    let warning_codes: Vec<&str> = env["warnings"]
        .as_array()
        .map(|a| a.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        warning_codes.contains(&refusal),
        "the {refusal} refusal must be reported: {env}"
    );
    assert_ne!(code, 0, "nothing was patched or attested: {env}");
    assert_eq!(env["summary"]["applied"], 0, "nothing redirected: {env}");
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
    let warning_codes: Vec<&str> = env["warnings"]
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
    assert_eq!(env["summary"]["applied"], 0, "nothing redirected: {env}");
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
    // A gem library's own sources (Driver::ScanVexGemspecDevDependency).
    if fx.proj.join(GEMSPEC_LIB).exists() {
        std::fs::copy(fx.proj.join(GEMSPEC_LIB), fresh.join(GEMSPEC_LIB)).unwrap();
        copy_dir_recursive(&fx.proj.join("lib"), &fresh.join("lib"));
    }
    copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    copy_dir_recursive(&fx.proj.join(".bundle"), &fresh.join(".bundle"));
    assert!(
        !fresh.join("vendor").exists(),
        "fresh checkout must not carry an installed tree (test bug)"
    );
    fresh
}

/// Fresh checkout + the FROZEN `bundle install` that CI and deploys run
/// (`BUNDLE_FROZEN=true`, bundler's deployment contract: exit 16 on any
/// Gemfile-vs-lock drift, the lock never written). The pair the scan wrote
/// must install as it is, on every bundler line. Returns the fresh dir and
/// the install output.
fn fresh_checkout_bundle_install(fx: &RedirectFixture) -> (PathBuf, Output) {
    let fresh = stage_fresh_checkout(fx, "fresh");
    let install = bundle_env(&fresh, &["install"], &[("BUNDLE_FROZEN", "true")]);
    (fresh, install)
}

/// The frozen install left the committed lock exactly as the scan wrote it.
fn assert_lock_untouched_by_install(fx: &RedirectFixture, fresh: &Path) {
    assert_eq!(
        std::fs::read_to_string(fresh.join(fx.lock_name)).unwrap(),
        std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap(),
        "a frozen install must leave {} byte-identical (bundler {})",
        fx.lock_name,
        fx.bundler.version
    );
}

/// One declaration form hosted mode edits where it stands (the fixture has
/// asserted the edit, and that the lock is the host bundler's own): a fresh
/// checkout's FROZEN install takes the patched bytes from the patch registry
/// and leaves the lock alone, and `rollback` hands the pre-scan pair back
/// byte for byte.
fn assert_form_installs_patched_and_rolls_back(fx: &RedirectFixture) {
    let (fresh, install) = fresh_checkout_bundle_install(fx);
    assert!(
        install.status.success(),
        "fresh-checkout frozen `bundle install` must succeed from the patch registry.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_lock_untouched_by_install(fx, &fresh);
    assert_patched_install(fx, &fresh);

    let api = fx._server.uri();
    let upstream = format!("{api}/upstream");
    let cwd = fx.proj.to_str().expect("utf8 tmp path");
    let (code, stdout, stderr) = run_socket_env(
        &fx.proj,
        &[
            "rollback",
            PURL,
            "--json",
            "--cwd",
            cwd,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            &api,
        ],
        &[("SOCKET_RUBYGEMS_URL", &upstream)],
    );
    assert_eq!(code, 0, "rollback:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&std::fs::read(fx.proj.join(fx.gemfile_name)).unwrap()),
        String::from_utf8_lossy(&fx.pristine_gemfile),
        "rollback must hand the {} back byte for byte",
        fx.gemfile_name
    );
    assert_eq!(
        String::from_utf8_lossy(&std::fs::read(fx.proj.join(fx.lock_name)).unwrap()),
        String::from_utf8_lossy(&fx.pristine_lock),
        "rollback must hand the {} back byte for byte",
        fx.lock_name
    );
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

/// A lock-only `git checkout` (or a merge that took the other side of the
/// lock): the Gemfile still gives the gem the patch-registry source, the
/// lock resolves it from upstream. v5 keeps no ledger, so that checkout has
/// nothing discovery reads (lockfile pins only). Both ways back are proven
/// with the REAL bundler: an unfrozen install re-resolves from the Gemfile,
/// and a hosted re-scan converges the lock itself — to the same bytes —
/// after which the pair attests from the lock alone.
async fn lock_only_revert_reconverges(fx: &RedirectFixture) {
    use vex_e2e_common::{assert_attested, run_vex, Marker};
    let bin = binary();
    let scanned_lock = std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap();
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

    // The scan's way back: the lock follows the Gemfile again.
    let rescan = stage_fresh_checkout(fx, "fresh-lock-only-revert-rescan");
    std::fs::write(rescan.join(fx.lock_name), &fx.pristine_lock).unwrap();
    let (code, stdout, stderr) = run_hosted_scan(&rescan, &fx._server.uri());
    assert_eq!(code, 0, "re-scan: {stdout}\nstderr:\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(rescan.join(fx.lock_name)).unwrap(),
        scanned_lock,
        "a re-scan must converge the reverted lock"
    );
    assert_eq!(
        std::fs::read(rescan.join(fx.gemfile_name)).unwrap(),
        std::fs::read(fx.proj.join(fx.gemfile_name)).unwrap(),
        "and leave the Gemfile as it is"
    );

    // Bundler's way back.
    let install = bundle(&dir, &["install"]);
    assert!(
        install.status.success(),
        "unfrozen install over the Gemfile-only pair (bundler {}):\n{}",
        fx.bundler.version,
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(dir.join(fx.lock_name)).unwrap(),
        scanned_lock,
        "bundler must re-resolve the gem from the Gemfile's `source:` option, to the lock \
         the scan writes"
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

    // FRESH-CHECKOUT PROOF (B1): the frozen install CI and deploys run
    // accepts the pair as the scan wrote it — a lock with no CHECKSUMS
    // section included — and pulls the patched .gem from the hosted
    // compact index.
    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "fresh-checkout frozen `bundle install` must succeed from the patch registry.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_lock_untouched_by_install(&fx, &fresh);
    assert_patched_install(&fx, &fresh);

    // The lock records the patch registry as the gem's source and the `!`
    // pin on the requirement the Gemfile declares (none here).
    let lock = std::fs::read_to_string(fresh.join(fx.lock_name)).unwrap();
    assert!(
        lock.contains(&format!("remote: {}", fx.index_url)),
        "the lock must record the patch-registry source:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\nDEPENDENCIES\n  {DEP}!\n")),
        "the lock must carry the source-pinned dependency, its requirement untouched:\n{lock}"
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
    manifest_only_revert_installs_upstream(&fx).await;
}

/// The other half-revert: the Gemfile is back at its pre-scan declaration
/// (a `git checkout` of it, or a merge that took the other side) while the
/// lock still resolves the gem from the patch registry. Bundler takes a gem
/// from the source its Gemfile declaration names, so the lock section is
/// not wiring. Proven with the REAL bundler on a fresh checkout of that
/// pair: a frozen install refuses it, an unfrozen one rewrites the lock to
/// the pre-scan lock and installs the UPSTREAM gem. So `vex` attests
/// nothing from that lock: not with the patched gem still installed from
/// before the revert, not on the fresh checkout, not after the install.
async fn manifest_only_revert_installs_upstream(fx: &RedirectFixture) {
    use vex_e2e_common::{assert_absent, run_vex};
    let bin = binary();
    let nothing_attests = |dir: &Path, when: &str| {
        for no_verify in [false, true] {
            let mut run = vex_run(fx);
            run.no_verify = no_verify;
            let out = run_vex(&bin, dir, &run);
            let cell = format!(
                "{when}, no_verify={no_verify} (bundler {})",
                fx.bundler.version
            );
            assert_eq!(out.code, Some(2), "{cell}: {out}");
            assert_eq!(
                out.envelope["error"]["code"], "manifest_not_found",
                "{cell}: {out}"
            );
            assert_absent(out.doc.as_ref(), PURL);
        }
    };

    // The patched gem installed, then the Gemfile reverted under it.
    let stale = stage_fresh_checkout(fx, "fresh-manifest-only-revert-installed");
    let install = bundle(&stale, &["install"]);
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert_patched_install(fx, &stale);
    std::fs::write(stale.join(fx.gemfile_name), &fx.pristine_gemfile).unwrap();
    nothing_attests(&stale, "Gemfile reverted, lock and patched install kept");

    // A fresh checkout of the same pair: what CI and a new clone get.
    let dir = stage_fresh_checkout(fx, "fresh-manifest-only-revert");
    let scanned_lock = std::fs::read(dir.join(fx.lock_name)).unwrap();
    std::fs::write(dir.join(fx.gemfile_name), &fx.pristine_gemfile).unwrap();
    nothing_attests(&dir, "Gemfile reverted, nothing installed");

    let frozen = bundle_env(&dir, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        !frozen.status.success(),
        "a frozen install must refuse a lock whose source the Gemfile does not name (bundler \
         {}):\n{}",
        fx.bundler.version,
        String::from_utf8_lossy(&frozen.stdout)
    );
    assert_eq!(
        std::fs::read(dir.join(fx.lock_name)).unwrap(),
        scanned_lock,
        "a frozen install never writes the lock"
    );

    // Bundler <= 2.0 persisted `BUNDLE_FROZEN: "true"` into the checkout's
    // `.bundle/config` on that frozen attempt; a developer's unfrozen
    // install runs from the committed config.
    copy_dir_recursive(&fx.proj.join(".bundle"), &dir.join(".bundle"));
    let install = bundle(&dir, &["install"]);
    assert!(
        install.status.success(),
        "unfrozen install over the lock-only pair (bundler {}):\n{}",
        fx.bundler.version,
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&std::fs::read(dir.join(fx.lock_name)).unwrap()),
        String::from_utf8_lossy(&fx.pristine_lock),
        "bundler must drop the lock section the Gemfile does not name (bundler {})",
        fx.bundler.version
    );
    let installed = std::fs::read(fresh_installed_lib(
        &dir,
        &format!("{DEP}-{DEP_VERSION}"),
        "vuln_gem.rb",
    ))
    .expect("the upstream gem is installed");
    assert_eq!(
        String::from_utf8_lossy(&installed),
        orig_lib(),
        "the install holds the UPSTREAM gem (bundler {})",
        fx.bundler.version
    );
    nothing_attests(&dir, "after bundler re-resolved from the Gemfile");
}

/// GET-DRIVEN TWIN of the main capstone: `get <uuid> --mode hosted` (v4.0,
/// the per-advisory selector) must leave the same committable redirect
/// state as `scan --mode hosted` — same Gemfile `source:` option, NO ledger,
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
    // asserted the missing ledger + the Gemfile `source:` option).
    assert!(
        !fx.proj.join(".socket/manifest.json").exists(),
        "get --mode hosted must NOT write the manifest (parity with scan --mode hosted)"
    );
    assert!(
        !fx.proj.join(".socket/blobs").exists(),
        "get --mode hosted must NOT persist blobs"
    );

    // FRESH-CHECKOUT PROOF: the frozen install pulls the patched .gem from
    // the hosted compact index.
    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "fresh-checkout frozen `bundle install` must succeed from the patch registry.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_lock_untouched_by_install(&fx, &fresh);
    assert_patched_install(&fx, &fresh);

    // The lock records the patch registry as the gem's source and the `!`
    // pin — identical to what the scan-driven capstone leaves behind
    // (parity by construction).
    let lock = std::fs::read_to_string(fresh.join(fx.lock_name)).unwrap();
    assert!(
        lock.contains(&format!("remote: {}", fx.index_url)),
        "the lock must record the patch-registry source:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\nDEPENDENCIES\n  {DEP}!\n")),
        "the lock must carry the source-pinned dependency:\n{lock}"
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

/// The `sha512-<base64>` SRI string of `bytes`.
fn sri(bytes: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
    )
}

/// The stub gemspec `gem spec --ruby` derives from a built `.gem`.
fn stub_gemspec(gem: &[u8]) -> Vec<u8> {
    let file = tempfile::Builder::new().suffix(".gem").tempfile().unwrap();
    std::fs::write(file.path(), gem).unwrap();
    let mut spec = Command::new("gem");
    spec.args(["spec", file.path().to_str().unwrap(), "--ruby"]);
    cache_env::isolate(&mut spec);
    let stub = spec.output().expect("failed to run gem spec");
    assert!(
        stub.status.success(),
        "gem spec --ruby:\n{}",
        String::from_utf8_lossy(&stub.stderr)
    );
    stub.stdout
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
    // The vendored half of each grant: the patched `.gem` and its stub
    // gemspec, so a hosted → vendored eject can fetch both.
    let mut results = serde_json::Map::new();
    for g in gems {
        let sha = sha256_hex(&g.gem);
        let hosted_url = format!(
            "{}/patch/gem/{}/{DEP_VERSION}/{TOKEN}/{}/{}-{DEP_VERSION}.gem",
            server.uri(),
            g.name,
            g.uuid,
            g.name
        );
        let index_url = format!("{}/patch-registry/gem/{TOKEN}/{}/", server.uri(), g.uuid);
        let stub = stub_gemspec(&g.gem);
        let base = format!("/artifacts/{}", g.uuid);
        let gem_url = format!("{}{base}/{}-{DEP_VERSION}.gem", server.uri(), g.name);
        let stub_url = format!("{}{base}/{}-{DEP_VERSION}.gemspec", server.uri(), g.name);
        results.insert(
            g.uuid.to_string(),
            serde_json::json!({
                "status": "granted",
                "url": hosted_url,
                "purl": purl(g),
                "artifacts": [
                    { "kind": "tarball", "url": gem_url,
                      "integrity": { "sha512": sri(&g.gem), "sha256": sha } },
                    { "kind": "gem-stub-gemspec", "url": stub_url,
                      "integrity": { "sha512": sri(&stub) } }
                ],
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
        );
        for (leaf, bytes) in [
            (format!("{}-{DEP_VERSION}.gem", g.name), g.gem.clone()),
            (format!("{}-{DEP_VERSION}.gemspec", g.name), stub),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("{base}/{leaf}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
                .mount(server)
                .await;
        }
    }
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

/// #1749: two gems hosted at once. On bundler < 2.2 the converged lock
/// holds ONE merged `GEM` section with a Socket remote per patch; lockfile
/// discovery gave up on that section, so a re-scan skipped both gems as
/// `redirect_unattributable` (exit 0), `vex` found no patch, and a
/// superseding patch never landed. Every bundler must re-scan clean, attest
/// both gems, and take the superseding patch.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler; \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_two_gems_rescan_supersede_and_attest() {
    let Some(fx) = redirect_scanned_project(
        "two-hosted-gems",
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
    const VULN_GEN2: &str = "10000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const TINY_GEN2: &str = "80000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const VULN_GEN3: &str = "9a9a9a9a-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let stage = fx.tmp.path().join("generation-stage");
    let vuln = |uuid: &'static str, lib: String| GenerationGem {
        name: DEP,
        uuid,
        deps: vec![format!("{TRANSITIVE}:>= 0")],
        lib_file: "vuln_gem.rb",
        orig: orig_lib(),
        gem: build_gem(
            &stage.join(uuid),
            DEP,
            DEP_VERSION,
            "vuln_gem.rb",
            &lib,
            &[TRANSITIVE],
        ),
        patched: lib,
    };
    let tiny_patched = TINY_LIB.replace("tiny-ok", "tiny-patched");
    let tiny_gem = build_gem(
        &stage.join(TINY_GEN2),
        TRANSITIVE,
        "1.0.0",
        "tiny_dep.rb",
        &tiny_patched,
        &[],
    );
    let tiny = || GenerationGem {
        name: TRANSITIVE,
        uuid: TINY_GEN2,
        deps: vec![],
        lib_file: "tiny_dep.rb",
        orig: TINY_LIB.to_string(),
        patched: tiny_patched.clone(),
        gem: tiny_gem.clone(),
    };
    let api = fx._server.uri();
    let gemfile_path = fx.proj.join(fx.gemfile_name);
    let lock_path = fx.proj.join(fx.lock_name);
    let scan = |what: &str| {
        let (code, stdout, stderr) = run_hosted_scan(&fx.proj, &api);
        assert_eq!(code, 0, "{what}: {stdout}\nstderr:\n{stderr}");
        assert!(
            !stdout.contains("redirect_unattributable"),
            "{what}: a hosted gem was skipped as unattributable:\n{stdout}"
        );
        stdout
    };
    // The scan converges the lock itself, so an unfrozen install has
    // nothing left to rewrite.
    let converge = |what: &str| {
        let scanned = std::fs::read_to_string(&lock_path).unwrap();
        let install = bundle(&fx.proj, &["install"]);
        assert!(
            install.status.success(),
            "{what}: bundle install:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&install.stdout),
            String::from_utf8_lossy(&install.stderr)
        );
        let lock = std::fs::read_to_string(&lock_path).unwrap();
        assert_eq!(
            lock, scanned,
            "{what}: bundler must leave the scan's lock as it is"
        );
        lock
    };

    // Both gems hosted: the direct one by its declaration's `source:`
    // option, the transitive one by an added line.
    mount_patch_generation(&fx._server, 2, &[vuln(VULN_GEN2, patched_lib()), tiny()]).await;
    scan("generation-2 scan");
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    assert!(
        gemfile.ends_with(&format!(
            "\n\ngem \"{TRANSITIVE}\", \"1.0.0\", source: \"{api}/patch-registry/gem/{TOKEN}/{TINY_GEN2}/\", \
             require: false # added by socket-patch (transitive dependency)\n"
        )),
        "the transitive gem gets one marked line:\n{gemfile}"
    );
    let lock = converge("generation 2");
    for uuid in [VULN_GEN2, TINY_GEN2] {
        assert!(lock.contains(uuid), "generation 2 lock:\n{lock}");
    }
    if !fx.bundler.at_least(2, 2) {
        assert_eq!(
            lock.lines().filter(|l| *l == "GEM").count(),
            1,
            "bundler < 2.2 merges every remote into one GEM section:\n{lock}"
        );
    }

    // An in-sync re-scan attributes both gems and changes nothing.
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    scan("in-sync re-scan");
    assert_eq!(std::fs::read_to_string(&gemfile_path).unwrap(), gemfile);
    assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), lock);

    // Manifest-less vex attests both patches from the lock.
    let doc_path = fx.tmp.path().join("two-gems-vex.json");
    let (code, stdout, stderr) = run_socket(
        &fx.proj,
        &[
            "vex",
            "--output",
            doc_path.to_str().unwrap(),
            "--product",
            PRODUCT,
            "--cwd",
            fx.proj.to_str().unwrap(),
            "--patch-server-url",
            &api,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    assert_eq!(code, 0, "vex: {stdout}\nstderr:\n{stderr}");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&doc_path).unwrap()).unwrap();
    // Both patches fix the same advisory, so they share one statement.
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "{doc}");
    assert_eq!(stmts[0]["status"], "not_affected", "{doc}");
    let mut subjects: Vec<&str> = stmts[0]["products"][0]["subcomponents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["@id"].as_str().unwrap())
        .collect();
    subjects.sort_unstable();
    assert_eq!(
        subjects,
        [format!("pkg:gem/{TRANSITIVE}@1.0.0").as_str(), PURL],
        "{doc}"
    );
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    for uuid in [VULN_GEN2, TINY_GEN2] {
        assert!(
            impact.contains(&format!("Socket patch {uuid} (redirected)")),
            "{doc}"
        );
    }

    // A superseding patch for vuln-gem lands; tiny-dep keeps its patch.
    mount_patch_generation(
        &fx._server,
        1,
        &[
            vuln(VULN_GEN3, patched_lib().replace("PATCHED", "PATCHED-GEN3")),
            tiny(),
        ],
    )
    .await;
    scan("generation-3 scan");
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    assert!(
        gemfile.contains(VULN_GEN3) && !gemfile.contains(VULN_GEN2) && gemfile.contains(TINY_GEN2),
        "generation 3 Gemfile:\n{gemfile}"
    );
    let lock = converge("generation 3");
    assert!(
        lock.contains(VULN_GEN3) && !lock.contains(VULN_GEN2) && lock.contains(TINY_GEN2),
        "generation 3 lock:\n{lock}"
    );
    // A cold checkout of the converged pair installs frozen.
    let fresh = stage_fresh_checkout(&fx, "two-gems-fresh-frozen");
    let frozen = bundle_env(&fresh, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        frozen.status.success(),
        "frozen install of the generation 3 pair:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr)
    );

    // The hosted → vendored eject (#1648) reads the same wiring: it takes
    // both gems instead of refusing the merged section as contested.
    let upstream = format!("{api}/upstream");
    let eject = |extra: &[&str]| {
        let mut argv = vec!["vendor", "--json"];
        argv.extend_from_slice(extra);
        argv.extend([
            "--cwd",
            fx.proj.to_str().unwrap(),
            "--api-url",
            &api,
            "--patch-server-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ]);
        let (code, stdout, stderr) =
            run_socket_env(&fx.proj, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
        assert_eq!(code, 0, "vendor {extra:?}: {stdout}\nstderr:\n{stderr}");
        let env: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        for purl in [PURL.to_string(), format!("pkg:gem/{TRANSITIVE}@1.0.0")] {
            assert!(
                env["events"]
                    .as_array()
                    .is_some_and(|e| e.iter().any(|e| e["purl"] == purl.as_str())),
                "vendor {extra:?} takes {purl}: {env}"
            );
        }
    };
    eject(&["--dry-run"]);
    assert_eq!(std::fs::read_to_string(&gemfile_path).unwrap(), gemfile);
    assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), lock);
    eject(&["--yes"]);
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        !gemfile.contains("/patch-registry/") && !lock.contains("/patch-registry/"),
        "the eject leaves no hosted remote:\n{gemfile}\n{lock}"
    );
    // A cold checkout of the vendored pair installs frozen and loads both
    // patched gems.
    let fresh = stage_fresh_checkout(&fx, "two-gems-ejected-frozen");
    let frozen = bundle_env(&fresh, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        frozen.status.success(),
        "frozen install of the ejected pair:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr)
    );
    let gen3_lib = patched_lib().replace("PATCHED", "PATCHED-GEN3");
    for (name, lib, want) in [
        (DEP, "vuln_gem.rb", &gen3_lib),
        (TRANSITIVE, "tiny_dep.rb", &tiny_patched),
    ] {
        let loaded = bundle(
            &fresh,
            &[
                "exec",
                "ruby",
                "-e",
                "print File.read(File.join(Gem.loaded_specs[ARGV[0]].full_gem_path, 'lib', ARGV[1]))",
                name,
                lib,
            ],
        );
        assert!(
            loaded.status.success(),
            "bundle exec loads {name}:\n{}",
            String::from_utf8_lossy(&loaded.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&loaded.stdout),
            *want,
            "{name} loads its patched bytes"
        );
    }
}

/// #1626 / #1688, B2: a superseding hosted re-scan moves the Gemfile's
/// `source:` option AND the lock to the new patch, whatever the lock's era
/// (a section of its own from bundler 2.2 on, a remote of the one merged
/// section before), so the pair stays frozen-installable. A `rollback` /
/// `remove` after it hands back the pre-scan pair, byte for byte.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler; \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_unwind_after_a_superseding_rescan_restores_the_pre_scan_pair() {
    for command in ["rollback", "remove"] {
        unwind_after_superseding_rescan(command).await;
    }
}

async fn unwind_after_superseding_rescan(command: &str) {
    let Some(fx) = redirect_scanned_project(
        &format!("unconverged-supersede-{command}"),
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
    const GEN2: &str = "10000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const GEN3: &str = "9a9a9a9a-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let stage = fx.tmp.path().join("generation-stage");
    let vuln = |uuid: &'static str, lib: String| GenerationGem {
        name: DEP,
        uuid,
        deps: vec![format!("{TRANSITIVE}:>= 0")],
        lib_file: "vuln_gem.rb",
        orig: orig_lib(),
        gem: build_gem(
            &stage.join(uuid),
            DEP,
            DEP_VERSION,
            "vuln_gem.rb",
            &lib,
            &[TRANSITIVE],
        ),
        patched: lib,
    };
    let api = fx._server.uri();
    mount_patch_generation(&fx._server, 2, &[vuln(GEN2, patched_lib())]).await;
    let (code, out, err) = run_hosted_scan(&fx.proj, &api);
    assert_eq!(code, 0, "{command}: gen 2 scan: {out}\n{err}");
    let install = bundle(&fx.proj, &["install"]);
    assert!(
        install.status.success(),
        "{command}: converge gen 2:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    mount_patch_generation(
        &fx._server,
        1,
        &[vuln(GEN3, patched_lib().replace("PATCHED", "PATCHED-GEN3"))],
    )
    .await;
    let (code, out, err) = run_hosted_scan(&fx.proj, &api);
    assert_eq!(code, 0, "{command}: gen 3 scan: {out}\n{err}");
    let gemfile_path = fx.proj.join(fx.gemfile_name);
    let lock_path = fx.proj.join(fx.lock_name);
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        gemfile.contains(GEN3) && !gemfile.contains(GEN2),
        "{command}: Gemfile:\n{gemfile}"
    );
    // The lock moves with the Gemfile on every bundler line, so the pair
    // stays converged and a frozen install accepts it.
    assert!(
        lock.contains(GEN3) && !lock.contains(GEN2),
        "{command}: lock:\n{lock}"
    );
    let frozen = bundle_env(&fx.proj, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        frozen.status.success(),
        "{command}: frozen install of the gen 3 pair:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        lock,
        "{command}: the frozen install leaves the gen 3 lock as is"
    );

    let upstream = format!("{api}/upstream");
    let cwd = fx.proj.to_str().expect("utf8 tmp path");
    let mut argv = vec![command, PURL, "--json", "--cwd", cwd];
    if command == "remove" {
        argv.push("--yes");
    }
    argv.extend([
        "--api-url",
        &api,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        &api,
    ]);
    let (code, stdout, stderr) =
        run_socket_env(&fx.proj, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
    assert_eq!(code, 0, "{command}: {stdout}\nstderr:\n{stderr}");
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        !gemfile.contains("patch-registry"),
        "{command}: the Gemfile is still wired to a Socket patch:\n{gemfile}"
    );
    assert!(
        !lock.contains("patch-registry"),
        "{command}: the lock is still wired to a Socket patch:\n{lock}"
    );
    // Exactly the pre-scan pair: the declaration was never rewritten, so
    // nothing of it is lost.
    assert_eq!(
        gemfile.as_bytes(),
        fx.pristine_gemfile,
        "{command}: the Gemfile must come back byte for byte"
    );
    assert_eq!(
        lock.as_bytes(),
        fx.pristine_lock,
        "{command}: the lock must come back byte for byte"
    );
    // The pair is consistent: a frozen install accepts it as is.
    let frozen = bundle_env(&fx.proj, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        frozen.status.success(),
        "{command}: frozen install after the unwind:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        lock,
        "{command}: the frozen install leaves the restored lock as is"
    );
}

/// #2090: one gem vendored, then another hosted. The vendored gem's lock
/// record names no `GEM` section (its spec came out of the only one), and
/// the hosted gem's patch-registry section sorts ahead of the upstream one.
/// Unwinding the vendored gem used to put its spec into the hosted gem's
/// section: a fresh `bundle install` then looked for it on the patch
/// registry and failed, and the hosted gem could no longer be unwound.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler; \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_vendored_unwind_beside_a_hosted_gem_restores_the_upstream_section() {
    for command in ["rollback", "remove"] {
        vendored_unwind_beside_a_hosted_gem(command).await;
    }
}

async fn vendored_unwind_beside_a_hosted_gem(command: &str) {
    let Some(fx) = redirect_scanned_project(
        &format!("vendored-beside-hosted-{command}"),
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
    // Bundler < 2.2 merges every remote into one GEM section, so no hosted
    // section can sort ahead of the upstream one there.
    if !fx.bundler.at_least(2, 2) {
        println!(
            "SKIP e2e_redirect_gem_build (vendored-beside-hosted-{command}): bundler {}: \
             per-source GEM sections need bundler >= 2.2",
            fx.bundler.version
        );
        return;
    }
    const VULN_GEN2: &str = "10000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    const TINY_GEN2: &str = "80000000-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let tiny_purl = format!("pkg:gem/{TRANSITIVE}@1.0.0");
    let api = fx._server.uri();
    let upstream = format!("{api}/upstream");
    let cwd = fx.proj.to_str().expect("utf8 tmp path");
    let gemfile_path = fx.proj.join(fx.gemfile_name);
    let lock_path = fx.proj.join(fx.lock_name);
    let socket = |what: &str, head: &[&str]| {
        let mut argv = head.to_vec();
        argv.extend([
            "--json",
            "--cwd",
            cwd,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            &api,
        ]);
        let (code, stdout, stderr) =
            run_socket_env(&fx.proj, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
        assert_eq!(
            code, 0,
            "{command}: {what}:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        stdout
    };
    let install = |what: &str, dir: &Path, frozen: bool| {
        let envs: &[(&str, &str)] = if frozen {
            &[("BUNDLE_FROZEN", "true")]
        } else {
            &[]
        };
        let out = bundle_env(dir, &["install"], envs);
        assert!(
            out.status.success(),
            "{command}: {what}: bundle install:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let assert_pristine = |what: &str| {
        assert_eq!(
            std::fs::read_to_string(&gemfile_path).unwrap(),
            String::from_utf8_lossy(&fx.pristine_gemfile),
            "{command}: {what}: the Gemfile must come back byte for byte"
        );
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            String::from_utf8_lossy(&fx.pristine_lock),
            "{command}: {what}: the lock must come back byte for byte"
        );
    };

    // Back to the upstream pair: the fixture's own hosted scan is not part
    // of this scenario.
    socket("unwind the fixture scan", &["rollback", PURL]);
    assert_pristine("fixture unwind");
    install("upstream pair", &fx.proj, false);

    // The first patch generation covers the direct gem only; vendor it.
    let stage = fx.tmp.path().join("generation-stage");
    let vuln_gem = build_gem(
        &stage.join(VULN_GEN2),
        DEP,
        DEP_VERSION,
        "vuln_gem.rb",
        &patched_lib(),
        &[TRANSITIVE],
    );
    let vuln = || GenerationGem {
        name: DEP,
        uuid: VULN_GEN2,
        deps: vec![format!("{TRANSITIVE}:>= 0")],
        lib_file: "vuln_gem.rb",
        orig: orig_lib(),
        patched: patched_lib(),
        gem: vuln_gem.clone(),
    };
    let tiny_patched = TINY_LIB.replace("tiny-ok", "tiny-patched");
    let tiny = GenerationGem {
        name: TRANSITIVE,
        uuid: TINY_GEN2,
        deps: vec![],
        lib_file: "tiny_dep.rb",
        orig: TINY_LIB.to_string(),
        gem: build_gem(
            &stage.join(TINY_GEN2),
            TRANSITIVE,
            "1.0.0",
            "tiny_dep.rb",
            &tiny_patched,
            &[],
        ),
        patched: tiny_patched,
    };
    mount_patch_generation(&fx._server, 2, &[vuln()]).await;
    socket("vendored scan", &["scan", "--mode", "vendored", "--yes"]);
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.starts_with(&format!(
            "PATH\n  remote: .socket/vendor/gem/{VULN_GEN2}/{DEP}-{DEP_VERSION}\n"
        )),
        "{command}: {DEP} must be vendored:\n{lock}"
    );
    install("vendored pair", &fx.proj, false);

    // The next generation also patches the transitive gem. A hosted scan
    // leaves the vendored gem alone and hosts the other one, whose section
    // bundler sorts ahead of the upstream one.
    mount_patch_generation(&fx._server, 1, &[vuln(), tiny]).await;
    socket("hosted scan", &["scan", "--mode", "hosted", "--yes"]);
    install("vendored and hosted pair", &fx.proj, false);
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    let hosted_remote = format!("{api}/patch-registry/gem/{TOKEN}/{TINY_GEN2}/");
    let remotes = gem_remotes(&lock);
    assert_eq!(
        remotes.first().copied(),
        Some(hosted_remote.as_str()),
        "{command}: the hosted section must be the lock's first GEM section:\n{lock}"
    );
    assert!(
        lock.contains(&format!("{VULN_GEN2}/{DEP}-{DEP_VERSION}\n")),
        "{command}: {DEP} must still be vendored:\n{lock}"
    );

    if command == "remove" {
        // Un-vendoring one gem keeps the other hosted, and a cold checkout
        // of that pair still installs.
        socket("remove the vendored gem", &["remove", PURL, "--yes"]);
        let lock = std::fs::read_to_string(&lock_path).unwrap();
        assert!(
            lock.contains(&format!(
                "GEM\n  remote: {hosted_remote}\n  specs:\n    {TRANSITIVE} (1.0.0)\n\n\
                 GEM\n  remote: {upstream}/\n  specs:\n    {DEP} ({DEP_VERSION})\n"
            )),
            "{command}: {DEP} must return to the upstream section:\n{lock}"
        );
        let fresh = stage_fresh_checkout(&fx, "one-gem-left-hosted");
        install("cold checkout with one gem left hosted", &fresh, true);
        assert_eq!(
            std::fs::read_to_string(fresh.join(fx.lock_name)).unwrap(),
            lock,
            "{command}: the frozen install leaves the lock as is"
        );
        socket("remove the hosted gem", &["remove", &tiny_purl, "--yes"]);
    } else {
        socket("rollback both gems", &["rollback"]);
    }
    assert_pristine("unwind of both gems");
    let fresh = stage_fresh_checkout(&fx, "unwound");
    install("cold checkout of the unwound pair", &fresh, true);
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
        "fresh-checkout frozen `bundle install` from gems.rb must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_lock_untouched_by_install(&fx, &fresh);
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
    // #1761: the standalone `vendor` eject of the same pin. Its dry run
    // must preview the refusal the wet run raises, not `eject_planned`.
    mount_vendored_grant(&fx).await;
    for dry_run in [true, false] {
        vendor_eject_keeps_the_hosted_group_pin(&fx, dry_run);
    }
}

/// #1761 on a converged CHECKSUMS-less lock (it resolves the hosted gem
/// from the patch registry): `vendor --dry-run` previewed `eject_planned`
/// (exit 0) while the wet eject refused `gemfile_declaration_not_editable`.
/// The scan writes that lock itself now; an unfrozen install over it has
/// nothing to change.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_group_block_pin_survives_a_refused_eject_of_a_converged_lock() {
    let Some(fx) = redirect_scanned_project(
        "group-block converged eject",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexGroupBlock,
    )
    .await
    else {
        return;
    };
    let lock = std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap();
    assert!(
        lock.contains(&format!("remote: {}", fx.index_url)),
        "converged:\n{lock}"
    );
    let install = bundle(&fx.proj, &["install"]);
    assert!(
        install.status.success(),
        "install of the converged pair:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap(),
        lock,
        "an unfrozen install has nothing to change in the lock the scan wrote"
    );
    mount_vendored_grant(&fx).await;
    for dry_run in [true, false] {
        vendor_eject_keeps_the_hosted_group_pin(&fx, dry_run);
    }
}

/// The other side of #1761: a top-level hosted gem the vendored backend
/// can wire previews a clean `vendor --dry-run` eject (exit 0), and the wet
/// `vendor` then ejects it. The dry run checks the Gemfile/lock edits over
/// the restored text; the hosted `source:` option still on the declaration
/// on disk must not be read as a source the user chose for the gem.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_pin_previews_and_runs_a_clean_eject() {
    let Some(fx) = redirect_scanned_project(
        "hosted clean eject",
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
    // Install the hosted pair: the lock the scan wrote already resolves the
    // gem from the patch registry, which the eject restores from.
    let install = bundle(&fx.proj, &["install"]);
    assert!(
        install.status.success(),
        "install of the hosted pair:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    mount_vendored_grant(&fx).await;
    let proj = fx.proj.to_str().expect("utf8 tmp path");
    let api = fx._server.uri();
    for dry_run in [true, false] {
        let before: Vec<Vec<u8>> = ["Gemfile", "Gemfile.lock"]
            .iter()
            .map(|f| std::fs::read(fx.proj.join(f)).unwrap())
            .collect();
        let mut argv = vec![
            "vendor",
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
        ];
        if dry_run {
            argv.push("--dry-run");
        }
        let label = format!("vendor eject (dry_run={dry_run})");
        let (code, stdout, stderr) = run_socket(&fx.proj, &argv);
        assert_eq!(code, 0, "{label}:\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert!(
            !stdout.contains("gemfile_declaration_not_editable"),
            "{label}: the hosted option is not the user's own source:\n{stdout}"
        );
        if dry_run {
            assert!(
                stdout.contains("eject_planned"),
                "{label}: previews the eject:\n{stdout}"
            );
            for (file, before) in ["Gemfile", "Gemfile.lock"].iter().zip(before) {
                assert_eq!(
                    std::fs::read(fx.proj.join(file)).unwrap(),
                    before,
                    "{label}: a dry run writes nothing to {file}"
                );
            }
        } else {
            let gemfile = std::fs::read_to_string(fx.proj.join("Gemfile")).unwrap();
            assert!(
                gemfile.contains("path: \".socket/vendor/gem/"),
                "{label}: the Gemfile now points at the vendored copy:\n{gemfile}"
            );
        }
    }
}

/// #1808: a hosted gem whose `Gemfile.lock` (or whole pair) is CRLF, as a
/// Git for Windows `autocrlf` checkout leaves it, ejects to vendored mode
/// like an LF one. The `vendor` eject and the `scan --mode vendored`
/// takeover agree dry and wet: both exit 0, and the wet run wires the
/// vendored copy with the lock still CRLF on every line instead of failing
/// `apply_failed` ("Gemfile.lock has no GEM section") and rolling back.
/// A CRLF Gemfile keeps CRLF on every line too (#1821).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_pin_with_a_crlf_lock_ejects_cleanly() {
    for (command, crlf_files) in [
        ("vendor", &["Gemfile.lock"][..]),
        ("vendor", &["Gemfile", "Gemfile.lock"][..]),
        ("scan", &["Gemfile", "Gemfile.lock"][..]),
    ] {
        let Some(fx) = redirect_scanned_project(
            "hosted crlf eject",
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
        let install = bundle(&fx.proj, &["install"]);
        assert!(
            install.status.success(),
            "install of the hosted pair:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        for file in crlf_files {
            let path = fx.proj.join(file);
            let text = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, text.replace('\n', "\r\n")).unwrap();
        }
        mount_vendored_grant(&fx).await;
        let proj = fx.proj.to_str().expect("utf8 tmp path");
        let api = fx._server.uri();
        let upstream = format!("{api}/upstream");
        for dry_run in [true, false] {
            let before: Vec<Vec<u8>> = ["Gemfile", "Gemfile.lock"]
                .iter()
                .map(|f| std::fs::read(fx.proj.join(f)).unwrap())
                .collect();
            let mut argv = vec![command];
            if command == "scan" {
                argv.extend(["--mode", "vendored"]);
            }
            argv.extend([
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
            let label = format!("{command} eject, CRLF {crlf_files:?} (dry_run={dry_run})");
            let (code, stdout, stderr) =
                run_socket_env(&fx.proj, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
            assert_eq!(code, 0, "{label}:\nstdout:\n{stdout}\nstderr:\n{stderr}");
            for bad in ["apply_failed", "eject_rolled_back", "no GEM section"] {
                assert!(!stdout.contains(bad), "{label}: {bad}:\n{stdout}");
            }
            if dry_run {
                for (file, before) in ["Gemfile", "Gemfile.lock"].iter().zip(before) {
                    assert_eq!(
                        std::fs::read(fx.proj.join(file)).unwrap(),
                        before,
                        "{label}: a dry run writes nothing to {file}"
                    );
                }
            } else {
                let gemfile = std::fs::read_to_string(fx.proj.join("Gemfile")).unwrap();
                assert!(
                    gemfile.contains("path: \".socket/vendor/gem/"),
                    "{label}: the Gemfile now points at the vendored copy:\n{gemfile}"
                );
                if crlf_files.contains(&"Gemfile") {
                    assert_eq!(
                        gemfile.matches('\n').count(),
                        gemfile.matches("\r\n").count(),
                        "{label}: every line of the Gemfile keeps CRLF:\n{gemfile:?}"
                    );
                }
                let lock = std::fs::read_to_string(fx.proj.join("Gemfile.lock")).unwrap();
                assert!(
                    lock.contains("PATH\r\n  remote: .socket/vendor/gem/"),
                    "{label}: the lock wires the vendored copy:\n{lock:?}"
                );
                assert_eq!(
                    lock.matches('\n').count(),
                    lock.matches("\r\n").count(),
                    "{label}: every line of the lock keeps CRLF:\n{lock:?}"
                );
            }
        }
    }
}

/// One refused `vendor` eject of the group-block fixture (#1761): dry or
/// wet, the eject is refused whole with `gemfile_declaration_not_editable`
/// and `eject_refused` (exit 1), and the hosted `Gemfile` /
/// `Gemfile.lock` stay byte-untouched.
fn vendor_eject_keeps_the_hosted_group_pin(fx: &RedirectFixture, dry_run: bool) {
    let before: Vec<Vec<u8>> = ["Gemfile", "Gemfile.lock"]
        .iter()
        .map(|f| std::fs::read(fx.proj.join(f)).unwrap())
        .collect();
    let proj = fx.proj.to_str().expect("utf8 tmp path");
    let api = fx._server.uri();
    let mut argv: Vec<&str> = vec![
        "vendor",
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
    ];
    if dry_run {
        argv.push("--dry-run");
    }
    let label = format!("vendor eject (dry_run={dry_run})");
    let upstream = format!("{api}/upstream");
    let (code, stdout, stderr) =
        run_socket_env(&fx.proj, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{label}: not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
    assert_eq!(code, 1, "{label} must refuse: {env}\nstderr:\n{stderr}");
    let events = env["events"].as_array().expect("events");
    assert_eq!(events.len(), 1, "{label}: {env}");
    assert_eq!(events[0]["action"], "failed", "{label}: {env}");
    assert_eq!(
        events[0]["errorCode"], "gemfile_declaration_not_editable",
        "{label}: {env}"
    );
    // #2091: the refusal says how to get out of it. The gem is declared in
    // a `group :development do` block, which one top-level option replaces,
    // and it is hosted already, so hosted mode is the mode to leave it to.
    let detail = events[0]["error"].as_str().unwrap_or_default();
    assert!(
        detail.contains("move it to the top level with the option `group: :development`")
            && detail.contains(&format!("or leave {DEP} to hosted mode (`--mode hosted`)")),
        "{label}: the refusal names both ways out: {env}"
    );
    assert_eq!(env["error"]["code"], "eject_refused", "{label}: {env}");
    assert!(
        !stdout.contains("eject_planned") && !stdout.contains("eject_rolled_back"),
        "{label}: refused before any restore (or a preview of one): {env}"
    );
    for (file, before) in ["Gemfile", "Gemfile.lock"].iter().zip(before) {
        assert_eq!(
            std::fs::read(fx.proj.join(file)).unwrap(),
            before,
            "{label}: {file} keeps its hosted wiring"
        );
    }
}

/// #1056: a gem the user declared inside their own `source "…" do` block
/// already has its source selected by that block (bundler locks it as
/// `name (= v)!`). Hosted mode re-points gems that come from the Gemfile's
/// default source only: the scan refuses this one
/// (`redirect_gem_source_option`, naming the block and the way out), writes
/// nothing, attests nothing, and the untouched project still installs.
/// #1476: the same holds when assignment-form `v = if … end` /
/// `w = case … end` constructs precede the gem inside the block.
/// #1509: and when the block's `source(` opener spans lines, or the block
/// is a `source(…) { … }` brace block.
/// #1531: and when the `source … do` follows `x = 1;` on its line.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_gem_in_a_user_source_block_is_refused_and_still_installs() {
    for (driver, label) in [
        (Driver::ScanVexSourceBlock, "source-block"),
        (
            Driver::ScanVexSourceBlockAssignment,
            "source-block-assignment",
        ),
        (
            Driver::ScanVexSourceBlockMultiLineOpener,
            "source-block-multi-line-opener",
        ),
        (Driver::ScanVexSourceBlockBraces, "source-block-braces"),
        (
            Driver::ScanVexSourceBlockAfterSemicolon,
            "source-block-after-semicolon",
        ),
    ] {
        let fx =
            redirect_scanned_project(label, Spelling::Gemfile, false, true, None, driver).await;
        assert!(fx.is_none(), "the {label} driver asserts in place");
    }
}

/// #2162: a Gemfile with two top-level `source` lines, which bundler 2.2 to
/// 2.7 lock into one `GEM` section with two remotes. The scan refuses the
/// gem and leaves the project installable, as for any lock it cannot
/// follow; the warning names the two top-level sources and the remedy
/// (the second source in a block, `bundle lock`), and after that remedy
/// the same scan wires the gem and bundler installs it frozen. See
/// [`assert_two_global_sources_remedy_wires`].
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (2.2 to 2.7 for this arm); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_two_top_level_sources_are_refused_with_the_block_remedy() {
    let fx = redirect_scanned_project(
        "two-global-sources",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexTwoGlobalSources,
    )
    .await;
    assert!(fx.is_none(), "the driver asserts in place");
}

/// A pin socket-patch 5.0 / 5.1 wrote: the declaration replaced by a
/// `source "<index-url>" do … end` block declaring the exact version, the
/// lock (one without CHECKSUMS) left on the registry — the pair a frozen
/// install refused (B1). This version no longer writes the block, so the
/// pair is built by hand over the fixture. Against the real bundler:
///
///   * a re-scan keeps the block as it is (a pin is never migrated to the
///     option form behind the user's back) and brings the lock in line with
///     it — to the bytes `bundle lock` writes — so a fresh checkout installs
///     the patched gem FROZEN; a second re-scan changes nothing;
///   * `vex` attests the installed pin;
///   * `rollback` / `remove` take the block off. The declaration it replaced
///     is not in the file, so the gem comes back as the exact pin the block
///     held and the run says so (`upstream_gem_declaration_pinned`); the
///     restored lock is again what `bundle lock` writes, and installs
///     upstream bytes frozen.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_source_block_pin_of_5_1_is_kept_healed_and_unwound_with_a_warning() {
    use vex_e2e_common::{assert_attested, run_vex, Marker};
    for command in ["rollback", "remove"] {
        let Some(fx) = redirect_scanned_project(
            &format!("5.1 block {command}"),
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
        let gemfile_path = fx.proj.join(fx.gemfile_name);
        let lock_path = fx.proj.join(fx.lock_name);
        let pristine = String::from_utf8(fx.pristine_gemfile.clone()).unwrap();
        // `bundle lock` for `gemfile` over the pre-scan lock, in a side dir.
        let bundler_lock = |name: &str, gemfile: &str| -> String {
            let dir = fx.tmp.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(fx.gemfile_name), gemfile).unwrap();
            std::fs::write(dir.join(fx.lock_name), &fx.pristine_lock).unwrap();
            copy_dir_recursive(&fx.proj.join(".bundle"), &dir.join(".bundle"));
            let out = bundle(&dir, &["lock"]);
            assert!(
                out.status.success(),
                "{command}: bundle lock ({name}):\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            std::fs::read_to_string(dir.join(fx.lock_name)).unwrap()
        };

        // The pair 5.1 left behind.
        let block_gemfile = with_source_block(&pristine, &fx.index_url);
        std::fs::write(&gemfile_path, &block_gemfile).unwrap();
        std::fs::write(&lock_path, &fx.pristine_lock).unwrap();
        let block_lock = bundler_lock("block-relock", &block_gemfile);
        assert!(
            block_lock.contains(&format!("  {DEP} (= {DEP_VERSION})!\n")),
            "bundler pins a source-block gem exactly, with `!` (test premise):\n{block_lock}"
        );

        for pass in ["heals the lock", "changes nothing"] {
            let (code, stdout, stderr) = run_hosted_scan(&fx.proj, &api);
            assert_eq!(
                code, 0,
                "{command}: re-scan ({pass}):\n{stdout}\nstderr:\n{stderr}"
            );
            assert!(
                !stdout.contains("redirect_gem_frozen_install"),
                "{command}: re-scan ({pass}): a converged pair has no frozen-install caveat:\n{stdout}"
            );
            assert_eq!(
                std::fs::read_to_string(&gemfile_path).unwrap(),
                block_gemfile,
                "{command}: re-scan ({pass}): the block is kept as it is"
            );
            assert_eq!(
                std::fs::read_to_string(&lock_path).unwrap(),
                block_lock,
                "{command}: re-scan ({pass}): the lock is the one bundler {} writes for the block",
                fx.bundler.version
            );
        }

        let fresh = stage_fresh_checkout(&fx, &format!("block-fresh-{command}"));
        let install = bundle_env(&fresh, &["install"], &[("BUNDLE_FROZEN", "true")]);
        assert!(
            install.status.success(),
            "{command}: frozen install of the healed pair:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&install.stdout),
            String::from_utf8_lossy(&install.stderr)
        );
        assert_lock_untouched_by_install(&fx, &fresh);
        assert_patched_install(&fx, &fresh);
        let out = run_vex(&binary(), &fresh, &vex_run(&fx));
        assert_eq!(
            out.code,
            Some(0),
            "{command}: vex over the block pin: {out}"
        );
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);

        let cwd = fx.proj.to_str().expect("utf8 tmp path");
        let mut argv = vec![command];
        if command == "remove" {
            argv.extend([PURL, "--yes"]);
        }
        argv.extend([
            "--json",
            "--cwd",
            cwd,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            &api,
        ]);
        let (code, stdout, stderr) = run_socket(&fx.proj, &argv);
        assert_eq!(code, 0, "{command}:\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert!(
            stdout.contains("upstream_gem_declaration_pinned"),
            "{command}: the unwind must say the declaration came back as an exact pin:\n{stdout}"
        );
        let restored_gemfile = pristine.replace(
            &format!("gem \"{DEP}\""),
            &format!("gem \"{DEP}\", \"{DEP_VERSION}\""),
        );
        assert_eq!(
            std::fs::read_to_string(&gemfile_path).unwrap(),
            restored_gemfile,
            "{command}: the declaration comes back as the exact pin the block held"
        );
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            bundler_lock("restored-relock", &restored_gemfile),
            "{command}: the restored lock is the one bundler {} writes for the restored Gemfile",
            fx.bundler.version
        );
        let fresh = stage_fresh_checkout(&fx, &format!("block-restored-{command}"));
        let install = bundle_env(&fresh, &["install"], &[("BUNDLE_FROZEN", "true")]);
        assert!(
            install.status.success(),
            "{command}: frozen install of the restored pair:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        assert_eq!(
            std::fs::read(fresh_installed_lib(
                &fresh,
                &format!("{DEP}-{DEP_VERSION}"),
                "vuln_gem.rb"
            ))
            .unwrap(),
            orig_lib().into_bytes(),
            "{command}: the upstream bytes are installed"
        );
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
        // The ledger-classification preview: the refusal is a `skipped`
        // event carrying the refusal's code (which never flips the exit
        // code), never a `verified` would-vendor event.
        assert_eq!(code, 0, "{label}: {env}");
        let row = &env["events"][0];
        assert_eq!(row["action"], "skipped", "{label}: {env}");
        assert_eq!(
            row["errorCode"], "gemfile_declaration_not_editable",
            "{label}: {env}"
        );
        assert_eq!(
            env["summary"]["verified"], 0,
            "{label}: nothing to vendor: {env}"
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

/// #1477: bundler 4's Gemfile `lockfile "custom.lock"` call makes bundler
/// read `custom.lock` just like the setting. The hosted scan used to pin
/// the leftover `Gemfile.lock`, rewrite the Gemfile, leave `custom.lock`
/// untouched and report no refusal, so every frozen install then failed;
/// it must refuse, write nothing, and still install frozen.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 4.0 for this arm); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_bundler4_gemfile_lockfile_call_redirects_nothing() {
    let fx = redirect_scanned_project(
        "custom-lockfile-dsl",
        Spelling::Gemfile,
        true,
        true,
        None,
        Driver::ScanVexCustomLockfileDsl,
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
/// to a Socket source the key overrides (bundler would keep loading the
/// unpatched git checkout while VEX attested `not_affected`).
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

/// #340, B2: a `gem` declaration that continues on the next line gains the
/// option after its last argument, on the continuation line. (A rewrite of
/// the first line alone orphaned `require: false` and bundler refused the
/// Gemfile; a refusal left the gem unpatched.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_multi_line_declaration_redirects_in_place_and_installs() {
    let Some(fx) = redirect_scanned_project(
        "multi-line",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexMultiLineDeclaration,
    )
    .await
    else {
        return;
    };
    assert_form_installs_patched_and_rolls_back(&fx);
}

/// #826, B2: in `gem "x"; gem "y"` the option goes before the `;` and the
/// second declaration stays. (A rewrite of the whole line deleted
/// `gem "y"`, so the next frozen install failed.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            run with a pinned toolchain via --ignored"]
async fn gem_hosted_semicolon_joined_declarations_redirect_in_place_and_install() {
    let Some(fx) = redirect_scanned_project(
        "semicolon-joined",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexSemicolonJoinedDeclaration,
    )
    .await
    else {
        return;
    };
    assert_form_installs_patched_and_rolls_back(&fx);
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
    assert_form_installs_patched_and_rolls_back(&fx);
}

/// #985: a gem library whose Gemfile's `gemspec` directive declares the
/// vulnerable gem as a development dependency AND whose Gemfile declares it
/// too. Bundler 2.7+ merges the two into one Gemfile dependency. The
/// redirect leaves the declaration's requirement alone, so the lock's
/// DEPENDENCIES entry keeps the requirement bundler recorded and only gains
/// the `!` (the fixture already proved the lock is the one the host bundler
/// writes): a fresh checkout's FROZEN install accepts the pair unchanged and
/// installs the patched bytes (a rewrite that pinned `= 1.0.0` there exited
/// 16). A vendored takeover, which bundler 2.7+ cannot frozen-install in
/// this shape (the vendored backend refuses it), must refuse before it
/// restores the hosted pin, in the preview too, or the gem ends up unpatched
/// in both modes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6); \
            run with a pinned toolchain via --ignored"]
async fn gem_hosted_gemspec_dev_dependency_frozen_install_accepts_the_pin() {
    let Some(fx) = redirect_scanned_project(
        "gemspec-dev-dependency",
        Spelling::Gemfile,
        true,
        true,
        None,
        Driver::ScanVexGemspecDevDependency,
    )
    .await
    else {
        return;
    };
    let lock = std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap();
    let want = format!("\nDEPENDENCIES\n  mylib!\n  {DEP}!\n");
    assert!(
        lock.contains(&want),
        "the dependency keeps its requirement and gains the `!` ({want:?}):\n{lock}"
    );
    let fresh = stage_fresh_checkout(&fx, "fresh-frozen");
    let install = bundle_env(&fresh, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        install.status.success(),
        "fresh-checkout frozen `bundle install` must accept the redirected pair.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_eq!(
        std::fs::read_to_string(fresh.join(fx.lock_name)).unwrap(),
        lock,
        "the frozen install must leave the lock byte-identical"
    );
    assert_patched_install(&fx, &fresh);
    if fx.bundler.at_least(2, 7) {
        // As in the #775 takeover test: the restore re-derives the upstream
        // sha256 only for a rubygems.org remote, so spell the mock upstream
        // that way (served via `SOCKET_RUBYGEMS_URL`). No bundler runs
        // after this point.
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
                vendor_takeover_keeps_the_hosted_group_pin(&fx, command, selector, dry_run);
            }
        }
    }
}

/// #340, B2: a `gem` declaration with an `if` modifier keeps the modifier:
/// the option goes before it. (A rewrite of the line dropped the condition
/// and declared the gem unconditionally; a refusal left the gem unpatched.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_conditional_declaration_redirects_in_place_and_installs() {
    let Some(fx) = redirect_scanned_project(
        "conditional",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexConditionalDeclaration,
    )
    .await
    else {
        return;
    };
    assert_form_installs_patched_and_rolls_back(&fx);
}

/// `if::ENV[…]` is a modifier too, not a hash label: the option goes before
/// it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            run with a pinned toolchain via --ignored"]
async fn gem_hosted_scoped_constant_modifier_redirects_in_place_and_installs() {
    let Some(fx) = redirect_scanned_project(
        "scoped-constant-modifier",
        Spelling::Gemfile,
        false,
        true,
        None,
        Driver::ScanVexScopedConstantModifier,
    )
    .await
    else {
        return;
    };
    assert_form_installs_patched_and_rolls_back(&fx);
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

/// #681: bundler's `mirror.all` sends the per-dep patch-registry source to
/// the mirror, which serves the upstream gem. The hosted scan used
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
            assert_eq!(env["summary"]["applied"], 0, "{env}");
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

    // The probe: the redirected Gemfile beside the lock's registry version,
    // installed unfrozen, so bundler resolves the gem from the registry's
    // `/info` and trips over the gem it then downloads. (The lock the scan
    // wrote is no probe of the contract: it records the gem's real
    // dependencies, so bundler 2.5 installs from it regardless, while
    // bundler 4 refuses it with "incorrect dependencies in the lockfile".)
    let fresh = stage_fresh_checkout(&fx, "fresh-unfrozen");
    std::fs::write(fresh.join(fx.lock_name), &fx.pristine_lock).unwrap();
    let install = bundle(&fresh, &["install"]);
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
/// FULLY CONVERGED: patch-registry GEM section holding the dep's spec, the
/// `!` on the DEPENDENCIES entry (its requirement as the user declared it),
/// patched CHECKSUMS sha (v5 keeps no ledger: a rollback re-resolves the
/// upstream sha from the registry). The old mixed-state rewrite (pin only,
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
        lock.contains(&format!("\nDEPENDENCIES\n  {DEP}!\n")),
        "DEPENDENCIES must carry the source-pinned entry, its requirement untouched:\n{lock}"
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
    // either, and bundler has nothing to rewrite in the lock.
    let fresh = stage_fresh_checkout(&fx, "fresh-unfrozen");
    let install = bundle(&fresh, &["install"]);
    assert!(
        install.status.success(),
        "unfrozen fresh-checkout install of the converged pair must succeed (the pinned \
         exit-37 mixed-state refusal is fixed).\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_eq!(
        std::fs::read(fresh.join(fx.lock_name)).unwrap(),
        lock_before,
        "an unfrozen install has nothing to change in the converged lock"
    );
    assert_patched_install(&fx, &fresh);
}

/// GRANT ROTATION, end to end (token A -> A -> B, same patch uuid): the
/// production reference endpoint rotates the grant-token path segment of the
/// index URL per request, so a periodic/CI re-scan sees a NEW index URL for
/// the SAME redirect. The re-scan must (1) be byte-idempotent under the same
/// grant, (2) refresh the `source:` option's URL IN PLACE under a rotated
/// grant, the lock's remote with it — exactly one Socket source, no stale
/// token anywhere, no ledger — and (3) leave a pair a fresh checkout installs
/// the patched bytes from, frozen. It must never stack a second option (or
/// a block) on the declaration with the stale token URL still live.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_rotated_grant_rescan_refreshes_source_option_and_installs() {
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
    assert_eq!(env["summary"]["applied"], 1, "envelope: {env}");
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
    assert_eq!(env["summary"]["applied"], 1, "envelope: {env}");
    let gemfile = std::fs::read_to_string(fx.proj.join("Gemfile"))
        .expect("read Gemfile after rotated-grant re-scan");
    // The whole edit is the URL inside the option: the same Gemfile with
    // the rotated grant's index URL where the first one stood.
    assert_eq!(
        gemfile,
        gemfile_after_run1.replace(&fx.index_url, &index_url_b),
        "the option's URL must be refreshed to the rotated grant in place"
    );
    assert_eq!(
        gemfile.matches("/patch-registry/gem/").count(),
        1,
        "exactly one Socket source, never stacked:\n{gemfile}"
    );
    assert!(
        !gemfile.contains(TOKEN),
        "the stale grant token must be gone from the Gemfile:\n{gemfile}"
    );
    // The lock follows, so the pair stays frozen-installable.
    assert_eq!(
        std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap(),
        lock_after_run1.replace(&fx.index_url, &index_url_b),
        "the lock's remote must be refreshed with the Gemfile"
    );
    assert_no_redirect_ledger(&fx.proj);

    // Fresh checkout of the rotated pair: the frozen install resolves the
    // patched gem from the rotated registry path and leaves the lock alone.
    let (fresh, install) = fresh_checkout_bundle_install(&fx);
    assert!(
        install.status.success(),
        "fresh-checkout frozen `bundle install` after rotation must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    assert_lock_untouched_by_install(&fx, &fresh);
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

/// #1224: a pin only the Gemfile holds — its `source:` option is there, the
/// lock still names the registry (what a reverted or regenerated lock, or a
/// pair socket-patch 5.0 / 5.1 wrote for a lock with no CHECKSUMS section,
/// looks like). A capped re-scan must count that pin as ALREADY:
/// `--max-new-patches 0` must not defer it, and brings the lock back in
/// line with the Gemfile; under a cap of 1 the run after the first must
/// spend its slot on the NEXT gem instead of re-counting the wired one as
/// NEW forever.
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
    let converged = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        !converged.contains("CHECKSUMS") && converged.contains(&fx.index_url),
        "the scan converges the CHECKSUMS-less lock:\n{converged}"
    );
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();

    // The Gemfile-only pin: the lock reverted to its registry version.
    std::fs::write(&lock_path, &fx.pristine_lock).unwrap();

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
    assert_eq!(
        std::fs::read_to_string(&gemfile_path).unwrap(),
        gemfile,
        "cap 0 re-scan: the Gemfile is already wired"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        converged,
        "cap 0 re-scan: the lock is brought back in line with the Gemfile"
    );

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
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    for (gem, patch) in [(DEP, UUID), (TRANSITIVE, TINY_GEN2)] {
        assert!(
            gemfile.contains(&registry(patch)),
            "run 2 must leave both gems wired ({gem} missing):\n{gemfile}"
        );
        assert!(
            lock.contains(&registry(patch)),
            "run 2: the lock follows the Gemfile ({gem} missing):\n{lock}"
        );
    }
    let env = run_capped_hosted_scan(&fx.proj, &api, "1");
    assert_eq!(rollout_counts(&env), (0, 0, 2, 0), "run 3: {env}");
    assert_eq!(
        std::fs::read_to_string(&gemfile_path).unwrap(),
        gemfile,
        "run 3 must leave the Gemfile byte-identical"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        lock,
        "run 3 must leave the lock byte-identical"
    );
}

/// #1224 (superseding shape): a newer patch for the same gem version, new
/// uuid, over a Gemfile-only pin (the lock reverted to its registry
/// version). `--max-new-patches 0` ("upgrade existing patches only") must
/// see the Gemfile's pin and UPGRADE it to the new uuid, the lock with it,
/// instead of deferring it as NEW and leaving the Gemfile on the superseded
/// patch.
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
    let gemfile_before = std::fs::read_to_string(fx.proj.join(fx.gemfile_name)).unwrap();
    let lock_before = std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap();
    std::fs::write(fx.proj.join(fx.lock_name), &fx.pristine_lock).unwrap();

    let env = run_capped_hosted_scan(&fx.proj, &api, "0");
    assert_eq!(rollout_counts(&env), (0, 1, 0, 0), "cap 0 re-scan: {env}");
    let gen2_url = format!("{api}/patch-registry/gem/{TOKEN}/{VULN_GEN2}/");
    assert_eq!(
        std::fs::read_to_string(fx.proj.join(fx.gemfile_name)).unwrap(),
        gemfile_before.replace(&fx.index_url, &gen2_url),
        "the Gemfile's option must move to the superseding patch, in place"
    );
    assert_eq!(
        std::fs::read_to_string(fx.proj.join(fx.lock_name)).unwrap(),
        lock_before.replace(&fx.index_url, &gen2_url),
        "the lock must converge on the superseding patch"
    );
}

/// Copy the committable files of `src` (manifest pair, `.bundle`, the
/// committed bundler cache) into a new dir: a fresh checkout with no
/// installed tree.
fn checkout_with_cache(fx: &RedirectFixture, src: &Path, name: &str) -> PathBuf {
    let fresh = fx.tmp.path().join(name);
    std::fs::create_dir_all(&fresh).unwrap();
    for file in [fx.gemfile_name, fx.lock_name] {
        std::fs::copy(src.join(file), fresh.join(file)).unwrap();
    }
    copy_dir_recursive(&src.join(".bundle"), &fresh.join(".bundle"));
    copy_dir_recursive(&src.join("vendor/cache"), &fresh.join("vendor/cache"));
    fresh
}

/// #1260 through one unwind `command` (`rollback` / `remove`): a project
/// that ran `bundle cache` while the hosted pin was live commits the
/// PATCHED archive, and bundler installs from its cache first: left there
/// after the unwind, a fresh checkout either fails on the restored upstream
/// checksum (exit 37) or keeps installing the patched bytes.
///
/// `refresh` (the default run): the unwind brings the archive, and the
/// project's installed gem, back to the upstream gem itself, so a fresh
/// frozen checkout installs the upstream bytes with no further step. With
/// `--no-gem-install-refresh` the unwind only names the file, and deleting
/// it must be the whole remedy.
fn unwind_names_the_patched_cached_archive(fx: &RedirectFixture, command: &str, refresh: bool) {
    let dir = stage_fresh_checkout(fx, &format!("cache-{command}-{refresh}"));
    let install = bundle(&dir, &["install"]);
    assert!(
        install.status.success(),
        "{command}: hosted install:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let cache_cmd = if fx.bundler.at_least(2, 0) {
        "cache"
    } else {
        "package"
    };
    let cache = bundle(&dir, &[cache_cmd]);
    assert!(
        cache.status.success(),
        "{command}: bundle {cache_cmd}:\n{}",
        String::from_utf8_lossy(&cache.stderr)
    );
    let archive = dir
        .join("vendor")
        .join("cache")
        .join(format!("{DEP}-{DEP_VERSION}.gem"));
    assert!(
        archive.is_file(),
        "{command}: bundle {cache_cmd} wrote no archive"
    );

    let api = fx._server.uri();
    let upstream = format!("{api}/upstream");
    let cwd = dir.to_str().expect("utf8 tmp path");
    let mut argv = vec![command, PURL, "--json", "--cwd", cwd];
    if command == "remove" {
        argv.push("--yes");
    }
    if !refresh {
        argv.push("--no-gem-install-refresh");
    }
    let cached_while_hosted = std::fs::read(&archive).unwrap();
    argv.extend([
        "--api-url",
        &api,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        &api,
    ]);
    let (code, stdout, stderr) = run_socket_env(&dir, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("{command}: not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(code, 0, "{command}: {env}\nstderr:\n{stderr}");
    let lock = std::fs::read_to_string(dir.join(fx.lock_name)).unwrap();
    assert!(
        !lock.contains(&fx.index_url),
        "{command}: the lock is back on upstream:\n{lock}"
    );
    let hits: Vec<&serde_json::Value> = env["warnings"]
        .as_array()
        .map(|w| {
            w.iter()
                .filter(|w| w["code"] == "upstream_gem_stale_cache")
                .collect()
        })
        .unwrap_or_default();
    let installed = fresh_installed_lib(&dir, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
    if refresh {
        assert!(
            hits.is_empty(),
            "{command}: the archive was refreshed, not warned about: {env}"
        );
        let refreshed = env["warnings"]
            .as_array()
            .map(|w| {
                w.iter()
                    .filter(|w| w["code"] == "upstream_gem_install_refreshed")
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            refreshed, 2,
            "{command}: the installed gem and the cached archive: {env}"
        );
        assert!(
            std::fs::read(&archive).unwrap() != cached_while_hosted,
            "{command}: the cached archive is no longer the patched gem"
        );
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            orig_lib().into_bytes(),
            "{command}: the installed gem is the upstream one again"
        );
        // Every reinstall keeps the upstream bytes, and so does a fresh
        // frozen checkout that carries the committed cache.
        for args in [&["install"][..], &["pristine"][..]] {
            let out = bundle(&dir, args);
            assert!(
                out.status.success(),
                "{command}: bundle {args:?} after the unwind:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                std::fs::read(&installed).unwrap(),
                orig_lib().into_bytes(),
                "{command}: bundle {args:?} keeps the upstream bytes"
            );
        }
        let fixed = checkout_with_cache(fx, &dir, &format!("cache-{command}-refreshed"));
        let install = bundle_env(&fixed, &["install"], &[("BUNDLE_FROZEN", "true")]);
        assert!(
            install.status.success(),
            "{command}: frozen install from the refreshed cache:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        let lib = fresh_installed_lib(&fixed, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
        assert_eq!(
            std::fs::read(&lib).unwrap(),
            orig_lib().into_bytes(),
            "{command}: the upstream bytes are installed"
        );
        return;
    }
    assert_eq!(hits.len(), 1, "{command}: one stale-cache warning: {env}");
    let detail = hits[0]["detail"].as_str().unwrap();
    assert!(
        detail.contains(&archive.display().to_string()),
        "{command}: the warning names the cached archive: {detail}"
    );
    assert!(
        std::fs::read(&archive).unwrap() == cached_while_hosted,
        "{command}: an opted-out unwind leaves the archive alone"
    );

    // The defect the warning is about: with the archive left in place a
    // fresh frozen checkout never installs the upstream bytes.
    let stale = checkout_with_cache(fx, &dir, &format!("cache-{command}-stale"));
    let install = bundle_env(&stale, &["install"], &[("BUNDLE_FROZEN", "true")]);
    let lib = fresh_installed_lib(&stale, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
    assert!(
        !install.status.success() || std::fs::read(&lib).unwrap() == fx.patched,
        "{command}: bundler {} must reuse the cached patched archive (test premise)",
        fx.bundler.version
    );

    // The remedy the warning prescribes: delete the archive and re-cache
    // (a frozen install with a committed cache dir reads only the cache
    // on some bundlers), and a fresh frozen checkout installs upstream.
    let recached = checkout_with_cache(fx, &dir, &format!("cache-{command}-recached"));
    std::fs::remove_file(
        recached
            .join("vendor/cache")
            .join(format!("{DEP}-{DEP_VERSION}.gem")),
    )
    .unwrap();
    let cache = bundle(&recached, &[cache_cmd]);
    assert!(
        cache.status.success(),
        "{command}: bundle {cache_cmd} after deleting the archive:\n{}",
        String::from_utf8_lossy(&cache.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(recached.join(fx.lock_name)).unwrap(),
        lock,
        "{command}: re-caching leaves the restored lock alone"
    );
    let fixed = checkout_with_cache(fx, &recached, &format!("cache-{command}-fixed"));
    let install = bundle_env(&fixed, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        install.status.success(),
        "{command}: frozen install from the re-cached checkout:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let lib = fresh_installed_lib(&fixed, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
    assert_eq!(
        std::fs::read(&lib).unwrap(),
        orig_lib().into_bytes(),
        "{command}: the upstream bytes are installed"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_unwind_names_a_patched_archive_in_vendor_cache() {
    let Some(fx) = redirect_scanned_project(
        "cache-unwind",
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
    for refresh in [true, false] {
        unwind_names_the_patched_cached_archive(&fx, "rollback", refresh);
        unwind_names_the_patched_cached_archive(&fx, "remove", refresh);
    }
}

/// #2092 against a real Bundler: the gem home has no `cache/` dir (Bundler
/// 4.1's `prune` setting, the `rm -rf "${BUNDLE_PATH}"/ruby/*/cache` of the
/// Dockerfile Rails generates), so the unwind has no archive to judge the
/// installed patched gem by. It judges the copy by the pin's patch record
/// and puts the upstream gem back. Left alone, `bundle install` would call
/// the bundle complete and keep the patched copy under the upstream lock.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17; CHECKSUMS arm >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_unwind_restores_an_install_whose_home_cache_was_pruned() {
    let Some(fx) = redirect_scanned_project(
        "pruned-unwind",
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
    for command in ["rollback", "remove"] {
        let dir = stage_fresh_checkout(&fx, &format!("pruned-{command}"));
        let install = bundle(&dir, &["install"]);
        assert!(
            install.status.success(),
            "{command}: hosted install:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        let installed = fresh_installed_lib(&dir, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            fx.patched,
            "{command}: the patched gem is installed (test premise)"
        );
        // <home>/gems/<leaf>/lib/<file>
        let home = installed.ancestors().nth(4).unwrap();
        std::fs::remove_dir_all(home.join("cache")).unwrap();

        let api = fx._server.uri();
        let upstream = format!("{api}/upstream");
        let cwd = dir.to_str().expect("utf8 tmp path");
        let mut argv = vec![command, PURL, "--json", "--cwd", cwd];
        if command == "remove" {
            argv.push("--yes");
        }
        argv.extend([
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            &api,
        ]);
        let (code, stdout, stderr) =
            run_socket_env(&dir, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
        let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("{command}: not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
        });
        assert_eq!(code, 0, "{command}: {env}\nstderr:\n{stderr}");
        let lock = std::fs::read_to_string(dir.join(fx.lock_name)).unwrap();
        assert!(
            !lock.contains(&fx.index_url),
            "{command}: the lock is back on upstream:\n{lock}"
        );
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            orig_lib().into_bytes(),
            "{command}: the installed gem is the upstream one again: {env}"
        );
        assert!(
            env.to_string().contains("upstream_gem_install_refreshed")
                && !env.to_string().contains("upstream_gem_stale_install"),
            "{command}: {env}"
        );
        assert!(
            !home.join("cache").exists(),
            "{command}: a pruned cache dir is not created"
        );
        // The restored project installs as it is, and keeps the upstream gem.
        let install = bundle(&dir, &["install"]);
        assert!(
            install.status.success(),
            "{command}: bundle install after the unwind:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            orig_lib().into_bytes(),
            "{command}: bundle install keeps the upstream bytes"
        );
    }
}

/// #2230 against a real Bundler: the project's `Gemfile` names a private
/// gem server as its source, so the lock (with `CHECKSUMS`) resolves the gem
/// from that remote, not rubygems.org. The unwind refuses to guess the
/// upstream sha256 and names `SOCKET_RUBYGEMS_URL`; with the setting naming
/// that server it reads the checksum from the server's compact index, hands
/// the pre-scan pair back byte for byte and puts the upstream gem back, so
/// `bundle install` and `bundle pristine` both pass on the restored lock.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (CHECKSUMS lock: >= 2.6); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_unwind_restores_a_gem_from_a_private_gem_server() {
    let Some(fx) = redirect_scanned_project(
        "mirror-unwind",
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
    let api = fx._server.uri();
    let upstream = format!("{api}/upstream");
    assert!(
        String::from_utf8_lossy(&fx.pristine_lock).contains(&format!("remote: {upstream}/")),
        "premise: the lock resolves the gem from the gem server"
    );
    for command in ["rollback", "remove"] {
        let dir = stage_fresh_checkout(&fx, &format!("mirror-{command}"));
        let install = bundle(&dir, &["install"]);
        assert!(
            install.status.success(),
            "{command}: hosted install:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        let installed = fresh_installed_lib(&dir, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            fx.patched,
            "{command}: the patched gem is installed (test premise)"
        );
        let pair = || {
            (
                std::fs::read(dir.join(fx.gemfile_name)).unwrap(),
                std::fs::read(dir.join(fx.lock_name)).unwrap(),
            )
        };
        let hosted = pair();

        let cwd = dir.to_str().expect("utf8 tmp path");
        let mut argv = vec![command, PURL, "--json", "--cwd", cwd];
        if command == "remove" {
            argv.push("--yes");
        }
        argv.extend([
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            &api,
        ]);
        // The registry setting names another server: refused, nothing
        // changed, and the refusal names the setting that works.
        let elsewhere = format!("{api}/elsewhere");
        let (code, stdout, stderr) =
            run_socket_env(&dir, &argv, &[("SOCKET_RUBYGEMS_URL", &elsewhere)]);
        assert_ne!(code, 0, "{command}:\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert!(
            format!("{stdout}{stderr}").contains(&format!("`SOCKET_RUBYGEMS_URL={upstream}`")),
            "{command}: the refusal names the setting:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            pair() == hosted,
            "{command}: a refused unwind changes nothing"
        );

        let (code, stdout, stderr) =
            run_socket_env(&dir, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
        let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("{command}: not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
        });
        assert_eq!(code, 0, "{command}: {env}\nstderr:\n{stderr}");
        let (gemfile, lock) = pair();
        assert_eq!(
            String::from_utf8_lossy(&gemfile),
            String::from_utf8_lossy(&fx.pristine_gemfile),
            "{command}: the Gemfile is the pre-scan one"
        );
        assert_eq!(
            String::from_utf8_lossy(&lock),
            String::from_utf8_lossy(&fx.pristine_lock),
            "{command}: the lock is the pre-scan one"
        );
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            orig_lib().into_bytes(),
            "{command}: the installed gem is the upstream one again: {env}"
        );
        assert!(
            !env.to_string().contains("upstream_gem_stale_install"),
            "{command}: {env}"
        );
        // The restored project installs and reinstalls as it is.
        for args in [&["install"][..], &["pristine"][..]] {
            let run = bundle(&dir, args);
            assert!(
                run.status.success(),
                "{command}: bundle {args:?} after the unwind:\n{}\n{}",
                String::from_utf8_lossy(&run.stdout),
                String::from_utf8_lossy(&run.stderr)
            );
            assert_eq!(
                std::fs::read(&installed).unwrap(),
                orig_lib().into_bytes(),
                "{command}: bundle {args:?} keeps the upstream bytes"
            );
        }
    }
}

/// A warm project: the pre-redirect pair installed from the mock upstream
/// into the project's `vendor/bundle`, as on a developer machine or a CI
/// job with a restored bundle cache.
fn stage_warm_install(fx: &RedirectFixture, name: &str) -> PathBuf {
    let dir = fx.tmp.path().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(fx.gemfile_name), &fx.pristine_gemfile).unwrap();
    std::fs::write(dir.join(fx.lock_name), &fx.pristine_lock).unwrap();
    copy_dir_recursive(&fx.proj.join(".bundle"), &dir.join(".bundle"));
    let install = bundle(&dir, &["install"]);
    assert!(
        install.status.success(),
        "warm install from the mock upstream:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    dir
}

/// The stale-install refresh against the real bundler (the "Gem
/// stale-install guard" section of CLI_CONTRACT.md): the upstream gem is
/// ALREADY installed when the hosted scan runs, which is where bundler
/// keeps the installed copy and reports success. The scan itself must
/// leave the patched gem installed, and every way of reinstalling
/// (`install`, `--redownload`, `pristine`, a frozen install) must succeed
/// and keep it: before the refresh they kept the upstream bytes, failed on
/// the pinned checksum (exit 37), or left the gem dir deleted.
///
/// `agent_patched` (#2089): agent mode patched the installed gem in place
/// before the hosted scan, and its manifest record proves it. The files
/// are the patched ones already, but the archive RubyGems reinstalls from
/// is still the upstream one, so `pristine` and `--redownload` removed the
/// gem and failed on the lock's checksum, or brought the unpatched gem
/// back. The scan must replace that archive, and leave the gem dir (where
/// agent mode keeps a native gem's original build) as it is.
async fn scan_refreshes_a_warm_install(tag: &str, checksums_lock: bool, agent_patched: bool) {
    let Some(fx) = redirect_scanned_project(
        tag,
        Spelling::Gemfile,
        checksums_lock,
        true,
        None,
        Driver::ScanVex,
    )
    .await
    else {
        return;
    };
    let dir = stage_warm_install(&fx, "warm");
    let lib = fresh_installed_lib(&dir, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
    assert_eq!(
        std::fs::read(&lib).unwrap(),
        orig_lib().into_bytes(),
        "premise: the upstream gem is installed before the scan"
    );
    // A file of agent mode's own inside the gem dir.
    let kept_in_gem_dir = agent_patched.then(|| {
        lib.parent()
            .and_then(Path::parent)
            .expect("<gem dir>/lib/<file>")
            .join(".socket-patch-kept")
    });
    if agent_patched {
        // What `scan --mode agent` leaves: the lib patched in place, the
        // record of it, and both blobs.
        std::fs::write(&lib, patched_lib()).unwrap();
        common::write_in_place_patch_record(
            &dir.join(".socket"),
            PURL,
            UUID,
            "lib/vuln_gem.rb",
            orig_lib().as_bytes(),
            patched_lib().as_bytes(),
        );
        std::fs::write(kept_in_gem_dir.as_ref().unwrap(), "kept").unwrap();
    }

    let api = fx._server.uri();
    let (code, stdout, stderr) = run_hosted_scan(&dir, &api);
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    let codes: Vec<&str> = env["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"redirect_gem_install_refreshed")
            && !codes.contains(&"redirect_gem_stale_install"),
        "the scan refreshes the installed gem itself: {env}"
    );
    assert_eq!(
        std::fs::read(&lib).unwrap(),
        patched_lib().into_bytes(),
        "the installed gem is the patched one right after the scan"
    );
    if let Some(kept) = &kept_in_gem_dir {
        assert!(
            kept.is_file(),
            "only the archive beside a gem patched in place is replaced"
        );
    }

    // With no CHECKSUMS section the scan leaves the lock for one unfrozen
    // `bundle install` to converge (`redirect_gem_frozen_install`); with
    // one, the pair is already what bundler writes.
    if !checksums_lock {
        let converge = bundle(&dir, &["install"]);
        assert!(
            converge.status.success(),
            "the converging install:\n{}",
            String::from_utf8_lossy(&converge.stderr)
        );
    }
    assert_patched_install(&fx, &dir);

    let redownload = if fx.bundler.at_least(2, 0) {
        "--redownload"
    } else {
        "--force"
    };
    let flavors: [(&[&str], &[(&str, &str)]); 4] = [
        (&["install"], &[]),
        (&["install", redownload], &[]),
        (&["pristine"], &[]),
        (&["install"], &[("BUNDLE_FROZEN", "true")]),
    ];
    for (args, envs) in flavors {
        let out = bundle_env(&dir, args, envs);
        assert!(
            out.status.success(),
            "bundle {args:?} {envs:?} after the refresh:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read(&lib).unwrap(),
            patched_lib().into_bytes(),
            "bundle {args:?} {envs:?} keeps the patched bytes"
        );
    }
    assert_patched_install(&fx, &dir);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_scan_refreshes_a_warm_install() {
    scan_refreshes_a_warm_install("warm-refresh", false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_scan_refreshes_a_warm_install_with_a_checksums_lock() {
    scan_refreshes_a_warm_install("warm-refresh-checksums", true, false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_scan_refreshes_an_agent_patched_warm_install() {
    scan_refreshes_a_warm_install("warm-refresh-agent", false, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_scan_refreshes_an_agent_patched_warm_install_with_a_checksums_lock() {
    scan_refreshes_a_warm_install("warm-refresh-agent-checksums", true, true).await;
}

/// The vendored half of the patch API for the fixture's patch: the
/// patched `.gem` (the last `build_gem` of `DEP` left it in the stage dir)
/// and the stub gemspec `gem spec --ruby` derives from it, beside the
/// hosted registry override. Priority 1, so it answers every later
/// `patches/package` call in place of the hosted-only grant.
async fn mount_vendored_grant(fx: &RedirectFixture) {
    let server = &fx._server;
    let gem_path = fx
        .tmp
        .path()
        .join("gem-stage")
        .join(format!("{DEP}-src"))
        .join(format!("{DEP}-{DEP_VERSION}.gem"));
    let gem = std::fs::read(&gem_path).expect("the patched .gem from build_gem");
    let stub = stub_gemspec(&gem);
    let base = format!("/artifacts/{UUID}");
    let gem_url = format!("{}{base}/{DEP}-{DEP_VERSION}.gem", server.uri());
    let stub_url = format!("{}{base}/{DEP}-{DEP_VERSION}.gemspec", server.uri());
    let patched_sha = sha256_hex(&gem);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": gem_url,
                    "purl": PURL,
                    "artifacts": [
                        { "kind": "tarball", "url": gem_url,
                          "integrity": { "sha512": sri(&gem), "sha256": patched_sha } },
                        { "kind": "gem-stub-gemspec", "url": stub_url,
                          "integrity": { "sha512": sri(&stub) } }
                    ],
                    "registryOverride": {
                        "kind": "rubygems-compact-index",
                        "indexUrl": fx.index_url,
                        "identifiers": {
                            "name": DEP,
                            "version": DEP_VERSION,
                            "gemChecksumSha256": patched_sha,
                        }
                    }
                }
            }
        })))
        .with_priority(1)
        .mount(server)
        .await;
    for (leaf, bytes) in [
        (format!("{DEP}-{DEP_VERSION}.gem"), gem),
        (format!("{DEP}-{DEP_VERSION}.gemspec"), stub),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("{base}/{leaf}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(server)
            .await;
    }
}

/// #1594 through one vendored unwind `command`: the hosted pin was live
/// when the project ran `bundle cache`, so `vendor/cache` holds the PATCHED
/// archive. A hosted → vendored takeover wires the gem through its path
/// source (the archive is unused while vendored), and the later unwind puts
/// the pair back on the upstream `GEM` entry, where bundler installs from
/// that archive first. The unwind must name the file, exactly as the hosted
/// unwind does (#1260).
fn vendored_unwind_names_the_patched_cached_archive(fx: &RedirectFixture, command: &str) {
    let dir = stage_fresh_checkout(fx, &format!("vendored-cache-{command}"));
    let install = bundle(&dir, &["install"]);
    assert!(
        install.status.success(),
        "{command}: hosted install:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let cache_cmd = if fx.bundler.at_least(2, 0) {
        "cache"
    } else {
        "package"
    };
    let cache = bundle(&dir, &[cache_cmd]);
    assert!(
        cache.status.success(),
        "{command}: bundle {cache_cmd}:\n{}",
        String::from_utf8_lossy(&cache.stderr)
    );
    let archive = dir
        .join("vendor")
        .join("cache")
        .join(format!("{DEP}-{DEP_VERSION}.gem"));
    assert!(
        archive.is_file(),
        "{command}: bundle {cache_cmd} wrote no archive"
    );

    let api = fx._server.uri();
    let upstream = format!("{api}/upstream");
    let cwd = dir.to_str().expect("utf8 tmp path");
    let common = [
        "--json",
        "--cwd",
        cwd,
        "--api-url",
        &api,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        &api,
    ];
    let envs = [("SOCKET_RUBYGEMS_URL", upstream.as_str())];

    // What bundler already holds when the takeover runs: the patched gem
    // it installed from the patch registry, and the patched archive.
    let installed = fresh_installed_lib(&dir, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
    let held = (
        std::fs::read(&installed).unwrap(),
        std::fs::read(&archive).unwrap(),
    );
    assert!(held.0 == patched_lib().into_bytes(), "{command}: premise");

    let mut takeover = vec!["get", UUID, "--mode", "vendored", "--yes"];
    takeover.extend(common);
    let (code, stdout, stderr) = run_socket_env(&dir, &takeover, &envs);
    assert_eq!(
        code, 0,
        "{command}: takeover:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The takeover leaves them alone: bundler loads the vendored copy from
    // now on, and resetting an unused copy to upstream would only cost a
    // download and leave an unpatched leftover.
    assert!(
        std::fs::read(&installed).unwrap() == held.0 && std::fs::read(&archive).unwrap() == held.1,
        "{command}: the takeover changed a gem bundler already held"
    );
    let gemfile = std::fs::read_to_string(dir.join(fx.gemfile_name)).unwrap();
    assert!(
        gemfile.contains(".socket/vendor/gem/"),
        "{command}: the takeover vendored the gem:\n{gemfile}"
    );
    // The takeover's own notice says the vendored copy shadows the archive
    // for now, not that installs already fail.
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let notice = env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["errorCode"] == "upstream_gem_stale_cache")
        .unwrap_or_else(|| panic!("{command}: the takeover names the archive: {env}"));
    assert!(
        notice["reason"]
            .as_str()
            .is_some_and(|r| r.contains("while the gem stays vendored")),
        "{command}: {notice}"
    );

    let mut argv: Vec<&str> = match command {
        "vendor --revert" => vec!["vendor", "--revert", "--yes"],
        "remove" => vec!["remove", PURL, "--yes"],
        _ => vec![command, PURL],
    };
    argv.extend(common);
    let (code, stdout, stderr) = run_socket_env(&dir, &argv, &envs);
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("{command}: not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(code, 0, "{command}: {env}\nstderr:\n{stderr}");
    let gemfile = std::fs::read_to_string(dir.join(fx.gemfile_name)).unwrap();
    assert!(
        !gemfile.contains(".socket/vendor/gem/"),
        "{command}: the gem is no longer vendored:\n{gemfile}"
    );
    let hits: Vec<String> = env["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["code"] == "upstream_gem_stale_cache")
        // `remove` and `vendor --revert` report a vendored unwind's
        // advisories as uncounted events, `rollback` in `warnings[]`.
        .chain(
            env["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["errorCode"] == "upstream_gem_stale_cache"),
        )
        .map(|w| w.to_string())
        .collect();
    assert_eq!(hits.len(), 1, "{command}: one stale-cache warning: {env}");
    assert!(
        hits[0].contains(&archive.display().to_string()),
        "{command}: the warning names the cached archive: {}",
        hits[0]
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); the unpinned `test` \
            job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_vendored_unwind_names_a_patched_archive_in_vendor_cache() {
    let Some(fx) = redirect_scanned_project(
        "vendored-cache-unwind",
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
    mount_vendored_grant(&fx).await;
    for command in ["remove", "rollback", "vendor --revert"] {
        vendored_unwind_names_the_patched_cached_archive(&fx, command);
    }
}

/// #2083 through one vendored unwind `command`: the project installed the
/// hosted pin, so its installed gem and the archive RubyGems keeps beside
/// it are the PATCHED build. A hosted → vendored takeover leaves them (the
/// vendored copy is loaded instead), and the later unwind puts the pair
/// back on the upstream `GEM` entry, where bundler loads the installed
/// copy again. The unwind must put the upstream gem back: the app then
/// loads the upstream code, and every kind of reinstall succeeds and
/// keeps it.
fn vendored_unwind_restores_the_installed_gem(fx: &RedirectFixture, command: &str) {
    let dir = stage_fresh_checkout(fx, &format!("vendored-install-{command}"));
    let install = bundle(&dir, &["install"]);
    assert!(
        install.status.success(),
        "{command}: hosted install:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let installed = fresh_installed_lib(&dir, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
    assert!(
        std::fs::read(&installed).unwrap() == patched_lib().into_bytes(),
        "{command}: premise"
    );

    let api = fx._server.uri();
    let upstream = format!("{api}/upstream");
    let cwd = dir.to_str().expect("utf8 tmp path");
    let common = [
        "--json",
        "--cwd",
        cwd,
        "--api-url",
        &api,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        &api,
    ];
    let envs = [("SOCKET_RUBYGEMS_URL", upstream.as_str())];
    let mut takeover = vec!["get", UUID, "--mode", "vendored", "--yes"];
    takeover.extend(common);
    let (code, stdout, stderr) = run_socket_env(&dir, &takeover, &envs);
    assert_eq!(
        code, 0,
        "{command}: takeover:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let vendored = bundle(&dir, &["install"]);
    assert!(
        vendored.status.success(),
        "{command}: vendored install:\n{}",
        String::from_utf8_lossy(&vendored.stderr)
    );
    assert!(
        std::fs::read(&installed).unwrap() == patched_lib().into_bytes(),
        "{command}: premise: the takeover and its install leave the installed copy"
    );

    let mut argv: Vec<&str> = match command {
        "vendor --revert" => vec!["vendor", "--revert", "--yes"],
        "remove" => vec!["remove", PURL, "--yes"],
        _ => vec![command, PURL],
    };
    argv.extend(common);
    let (code, stdout, stderr) = run_socket_env(&dir, &argv, &envs);
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("{command}: not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(code, 0, "{command}: {env}\nstderr:\n{stderr}");
    assert!(
        env.to_string().contains("upstream_gem_install_refreshed")
            && !env.to_string().contains("upstream_gem_stale_install"),
        "{command}: {env}"
    );
    assert!(
        std::fs::read(&installed).unwrap() == orig_lib().into_bytes(),
        "{command}: the installed copy is the upstream build again: {env}"
    );

    let redownload = if fx.bundler.at_least(2, 0) {
        "--redownload"
    } else {
        "--force"
    };
    let probe = "require \"vuln_gem\"; print VulnGem.status";
    for args in [&["install"][..], &["install", redownload], &["pristine"]] {
        let out = bundle(&dir, args);
        assert!(
            out.status.success(),
            "{command}: bundle {args:?} after the unwind:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let run = bundle(&dir, &["exec", "ruby", "-e", probe]);
        assert_eq!(
            String::from_utf8_lossy(&run.stdout),
            "VULNERABLE",
            "{command}: bundle {args:?} leaves the upstream code loaded:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); the unpinned `test` \
            job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_vendored_unwind_restores_an_install_the_hosted_scan_patched() {
    let Some(fx) = redirect_scanned_project(
        "vendored-install-unwind",
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
    mount_vendored_grant(&fx).await;
    for command in ["remove", "rollback", "vendor --revert"] {
        vendored_unwind_restores_the_installed_gem(&fx, command);
    }
}

/// #2093 through one vendored unwind `command`: agent mode patched the
/// installed gem in place, and a vendored takeover then moved its manifest
/// record into the vendor ledger and left the patched files (the vendored
/// copy is loaded instead). The later unwind puts the pair back on the
/// upstream `GEM` entry, where bundler loads the installed copy again,
/// and nothing is left that records the patch. The unwind must put the
/// upstream gem back: the app then loads the upstream code, and every
/// kind of reinstall succeeds and keeps it.
fn vendored_unwind_restores_an_agent_patched_gem(fx: &RedirectFixture, command: &str) {
    let dir = stage_warm_install(fx, &format!("agent-vendored-{command}"));
    let installed = fresh_installed_lib(&dir, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb");
    assert!(
        std::fs::read(&installed).unwrap() == orig_lib().into_bytes(),
        "{command}: premise: the upstream gem is installed"
    );
    // What `scan --mode agent` leaves: the lib patched in place, the
    // record of it, and both blobs.
    std::fs::write(&installed, patched_lib()).unwrap();
    common::write_in_place_patch_record(
        &dir.join(".socket"),
        PURL,
        UUID,
        "lib/vuln_gem.rb",
        orig_lib().as_bytes(),
        patched_lib().as_bytes(),
    );

    let api = fx._server.uri();
    let upstream = format!("{api}/upstream");
    let cwd = dir.to_str().expect("utf8 tmp path");
    let common = [
        "--json",
        "--cwd",
        cwd,
        "--api-url",
        &api,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        &api,
    ];
    let envs = [("SOCKET_RUBYGEMS_URL", upstream.as_str())];
    let mut takeover = vec!["get", UUID, "--mode", "vendored", "--yes"];
    takeover.extend(common);
    let (code, stdout, stderr) = run_socket_env(&dir, &takeover, &envs);
    assert_eq!(
        code, 0,
        "{command}: takeover:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("vendor_manifest_record_migrated"),
        "{command}: premise: the takeover owns the record now:\n{stdout}"
    );
    let vendored = bundle(&dir, &["install"]);
    assert!(
        vendored.status.success(),
        "{command}: vendored install:\n{}",
        String::from_utf8_lossy(&vendored.stderr)
    );
    assert!(
        std::fs::read(&installed).unwrap() == patched_lib().into_bytes(),
        "{command}: premise: the takeover and its install leave the installed copy"
    );

    let mut argv: Vec<&str> = match command {
        "vendor --revert" => vec!["vendor", "--revert", "--yes"],
        "remove" => vec!["remove", PURL, "--yes"],
        _ => vec![command, PURL],
    };
    argv.extend(common);
    let (code, stdout, stderr) = run_socket_env(&dir, &argv, &envs);
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("{command}: not JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(code, 0, "{command}: {env}\nstderr:\n{stderr}");
    assert!(
        env.to_string().contains("upstream_gem_install_refreshed")
            && !env.to_string().contains("upstream_gem_stale_install"),
        "{command}: {env}"
    );
    assert!(
        std::fs::read(&installed).unwrap() == orig_lib().into_bytes(),
        "{command}: the installed copy is the upstream gem again: {env}"
    );

    let redownload = if fx.bundler.at_least(2, 0) {
        "--redownload"
    } else {
        "--force"
    };
    let probe = "require \"vuln_gem\"; print VulnGem.status";
    for args in [&["install"][..], &["install", redownload], &["pristine"]] {
        let out = bundle(&dir, args);
        assert!(
            out.status.success(),
            "{command}: bundle {args:?} after the unwind:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let run = bundle(&dir, &["exec", "ruby", "-e", probe]);
        assert_eq!(
            String::from_utf8_lossy(&run.stdout),
            "VULNERABLE",
            "{command}: bundle {args:?} leaves the upstream code loaded:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); the unpinned `test` \
            job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_vendored_unwind_restores_an_install_agent_mode_patched() {
    let Some(fx) = redirect_scanned_project(
        "agent-vendored-unwind",
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
    mount_vendored_grant(&fx).await;
    for command in ["remove", "rollback", "vendor --revert"] {
        vendored_unwind_restores_an_agent_patched_gem(&fx, command);
    }
}

/// #1831: a hosted redirect over a CRLF Gemfile (a Windows checkout, or
/// `core.autocrlf=true`) keeps it CRLF throughout: the edit is the option
/// alone, the real bundler installs the pair frozen and has nothing to
/// change in the lock, a re-scan is a no-op, and `rollback` hands back the
/// CRLF Gemfile byte for byte.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_redirect_keeps_a_crlf_gemfile_crlf() {
    let Some(fx) = redirect_scanned_project(
        "crlf-gemfile",
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
    let gemfile_path = fx.proj.join(fx.gemfile_name);
    let lock_path = fx.proj.join(fx.lock_name);
    let scanned_lock = std::fs::read_to_string(&lock_path).unwrap();
    // Start over from the pristine pair, its Gemfile in CRLF.
    let pristine = String::from_utf8(fx.pristine_gemfile.clone()).unwrap();
    let crlf = pristine.replace("\r\n", "\n").replace('\n', "\r\n");
    let _ = std::fs::remove_dir_all(fx.proj.join(".socket"));
    std::fs::write(&gemfile_path, &crlf).unwrap();
    std::fs::write(&lock_path, &fx.pristine_lock).unwrap();

    let (code, out, err) = run_hosted_scan(&fx.proj, &api);
    assert_eq!(code, 0, "hosted scan: {out}\n{err}");
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    assert_eq!(
        gemfile,
        with_source_option(&crlf, &format!("gem \"{DEP}\""), &fx.index_url),
        "the CRLF Gemfile gains the option and nothing else"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        scanned_lock,
        "the lock converges as it does beside an LF Gemfile"
    );

    let install = bundle_env(&fx.proj, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        install.status.success(),
        "frozen install of the CRLF Gemfile's pair:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let (code, out, err) = run_hosted_scan(&fx.proj, &api);
    assert_eq!(code, 0, "re-scan: {out}\n{err}");
    assert_eq!(
        std::fs::read_to_string(&gemfile_path).unwrap(),
        gemfile,
        "a re-scan leaves the Gemfile byte-identical"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        scanned_lock,
        "a re-scan leaves the lock byte-identical"
    );

    let upstream = format!("{api}/upstream");
    let cwd = fx.proj.to_str().expect("utf8 tmp path");
    let (code, stdout, stderr) = run_socket_env(
        &fx.proj,
        &[
            "rollback",
            PURL,
            "--json",
            "--cwd",
            cwd,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            &api,
        ],
        &[("SOCKET_RUBYGEMS_URL", &upstream)],
    );
    assert_eq!(code, 0, "rollback: {stdout}\nstderr:\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(&gemfile_path).unwrap(),
        crlf,
        "rollback hands the CRLF Gemfile back byte for byte"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        fx.pristine_lock,
        "rollback hands the lock back byte for byte"
    );
}

/// Publish `DEP` 1.1.0 on the mock upstream, the way rubygems.org does: one
/// more line in the gem's `/info` and one appended to `/versions`. The
/// routes outrank the fixture's own (wiremock priority 1 over the default 5).
async fn release_upstream_1_1_0(fx: &RedirectFixture) {
    let api = fx._server.uri();
    let gem = build_gem(
        &fx.tmp.path().join("gem-stage-next"),
        DEP,
        "1.1.0",
        "vuln_gem.rb",
        &orig_lib(),
        &[TRANSITIVE],
    );
    let fetch = |route: String| async move {
        reqwest::get(route)
            .await
            .expect("mock upstream reachable")
            .text()
            .await
            .expect("compact index body")
    };
    let info = format!(
        "{}1.1.0 {TRANSITIVE}:>= 0|checksum:{}\n",
        fetch(format!("{api}/upstream/info/{DEP}")).await,
        sha256_hex(&gem)
    );
    let versions = format!(
        "{}{DEP} 1.1.0 {}\n",
        fetch(format!("{api}/upstream/versions")).await,
        md5_hex(info.as_bytes())
    );
    for (route, response) in [
        (format!("/upstream/info/{DEP}"), compact_index_body(info)),
        (
            "/upstream/versions".to_owned(),
            compact_index_body(versions),
        ),
        (
            format!("/upstream/gems/{DEP}-1.1.0.gem"),
            ResponseTemplate::new(200).set_body_raw(gem, "application/octet-stream"),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(response)
            .with_priority(1)
            .mount(&fx._server)
            .await;
    }
}

/// Serve the patch record's purl the way the patch service spells a gem
/// record's: with its `?platform=ruby` qualifier, on every route that
/// carries it (the package a batch result is filed under stays bare). Each
/// route answers what the fixture's own does, respelled, and outranks it.
async fn serve_record_purl_with_platform(fx: &RedirectFixture) {
    let api = fx._server.uri();
    let bare = format!("\"purl\":\"{PURL}\"");
    let qualified = format!("\"purl\":\"{PURL}?platform=ruby\"");
    let client = reqwest::Client::new();
    let post = |route: &str| client.post(format!("{api}{route}")).body("{}");
    let get = |route: &str| client.get(format!("{api}{route}"));
    let batch = format!("/v0/orgs/{ORG}/patches/batch");
    let by_package = format!("/v0/orgs/{ORG}/patches/by-package/{DEP}");
    let reference = format!("/v0/orgs/{ORG}/patches/package");
    let view = format!("/v0/orgs/{ORG}/patches/view/{UUID}");
    for (verb, route, request, keep_first) in [
        ("POST", batch.as_str(), post(&batch), true),
        ("GET", by_package.as_str(), get(&by_package), false),
        ("POST", reference.as_str(), post(&reference), false),
        ("GET", view.as_str(), get(&view), false),
    ] {
        let body = request
            .send()
            .await
            .expect("fixture API reachable")
            .text()
            .await
            .expect("fixture API body");
        assert!(body.contains(&bare), "{route} carries the purl: {body}");
        let respelled = if keep_first {
            let (head, tail) = body.split_once(&bare).expect("checked above");
            format!("{head}{bare}{}", tail.replace(&bare, &qualified))
        } else {
            body.replace(&bare, &qualified)
        };
        assert!(respelled.contains(&qualified), "{route}: {respelled}");
        let matcher = if route == by_package {
            Mock::given(method(verb)).and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.+$"
            )))
        } else {
            Mock::given(method(verb)).and(path(route))
        };
        matcher
            .respond_with(ResponseTemplate::new(200).set_body_raw(respelled, "application/json"))
            .with_priority(1)
            .mount(&fx._server)
            .await;
    }
}

/// The words a bash with `nullglob` set reads `command` as: a word that
/// holds an unquoted glob character and matches no file is dropped.
fn bash_nullglob_words(cwd: &Path, command: &str) -> Vec<String> {
    let out = Command::new("bash")
        .args(["-O", "nullglob", "-c", &format!("printf '%s\\n' {command}")])
        .current_dir(cwd)
        .output()
        .expect("bash runs");
    assert!(out.status.success(), "bash reads `{command}`: {out:?}");
    String::from_utf8(out.stdout)
        .expect("utf8 words")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A hosted gem's only source is its patch's registry, which serves one
/// version, so the gem leaves `bundle outdated` and `bundle update` cannot
/// move it (#2070). The scan has to say so, and what it says has to be true
/// of the real Bundler: with a newer upstream release out, `bundle outdated`
/// lists the gem before the scan and not after, `bundle update` leaves the
/// scanned lock at the patched version, and the way past the hold the scan
/// names (`rollback`, then `bundle update <gem>`) does move the gem.
///
/// The `rollback` it names is run as printed, through a shell (#2182): the
/// record's purl carries `?platform=ruby`, which selects no hosted pin and
/// which a shell globs, so the command names the pin without it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 1.17); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_scan_says_the_gem_is_held_at_its_version() {
    let Some(fx) = redirect_scanned_project(
        "update-hold",
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
    let upstream = format!("{api}/upstream");
    let cwd = fx.proj.to_str().expect("utf8 tmp path");
    let lock_path = fx.proj.join(fx.lock_name);
    let rollback = || {
        let (code, stdout, stderr) = run_socket_env(
            &fx.proj,
            &[
                "rollback",
                PURL,
                "--json",
                "--cwd",
                cwd,
                "--api-url",
                &api,
                "--org",
                ORG,
                "--api-token",
                "fake",
                "--patch-server-url",
                &api,
            ],
            &[("SOCKET_RUBYGEMS_URL", &upstream)],
        );
        assert_eq!(code, 0, "rollback:\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert_eq!(
            String::from_utf8_lossy(&std::fs::read(&lock_path).unwrap()),
            String::from_utf8_lossy(&fx.pristine_lock),
            "rollback hands the lock back byte for byte"
        );
    };
    // Bundler with a cold compact-index cache, so each call reads the
    // upstream index as it stands now.
    let bundle_cold = |args: &[&str]| {
        let _ = std::fs::remove_dir_all(fx.proj.join(".bundle-user-home"));
        let out = bundle(&fx.proj, args);
        (
            out.status.success(),
            format!(
                "stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let locked = |version: &str| {
        std::fs::read_to_string(&lock_path)
            .unwrap()
            .contains(&format!("    {DEP} ({version})\n"))
    };

    // Back to the pre-scan pair, and upstream releases 1.1.0.
    rollback();
    release_upstream_1_1_0(&fx).await;
    let (up_to_date, before) = bundle_cold(&["outdated"]);
    assert!(
        !up_to_date && before.contains(DEP) && before.contains("1.1.0"),
        "control: before the scan `bundle outdated` reports {DEP} 1.0.0 -> 1.1.0:\n{before}"
    );

    // The scan, in human output: it names the gem it now holds and the way
    // past the hold.
    serve_record_purl_with_platform(&fx).await;
    let (code, stdout, stderr) = run_socket(
        &fx.proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--yes",
            "--cwd",
            cwd,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    assert_eq!(code, 0, "scan:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let note = format!(
        "Bundler now takes {DEP} from its Socket patch source only, which serves the patched \
         version and no other: `bundle outdated` no longer lists it and `bundle update` cannot \
         move it. To move it to a newer release, run `socket-patch rollback {PURL}`, \
         then `bundle update {DEP}`, then `socket-patch scan` again."
    );
    assert!(
        stdout.lines().any(|line| line == note),
        "the scan says {DEP} is held at its version:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let scanned_lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(locked(DEP_VERSION), "scanned lock:\n{scanned_lock}");

    // What the line says is so: the gem is gone from `bundle outdated`, and
    // `bundle update` leaves it at the patched version.
    let (up_to_date, after) = bundle_cold(&["outdated"]);
    assert!(
        up_to_date && !after.contains(DEP) && !after.contains("1.1.0"),
        "after the scan `bundle outdated` no longer reports {DEP}:\n{after}"
    );
    let (updated, update) = bundle_cold(&["update"]);
    assert!(updated, "`bundle update` on the scanned pair:\n{update}");
    assert!(
        locked(DEP_VERSION) && !locked("1.1.0"),
        "`bundle update` cannot move the held gem:\n{}",
        std::fs::read_to_string(&lock_path).unwrap()
    );

    // And the way past it works: roll back, then `bundle update <gem>`.
    // The rollback is the command the note printed, as a shell reads it.
    std::fs::write(&lock_path, &scanned_lock).unwrap();
    let printed = stdout
        .lines()
        .find(|line| line.starts_with("Bundler now takes "))
        .and_then(|line| {
            line.split('`')
                .find(|span| span.starts_with("socket-patch rollback "))
        })
        .expect("the scan's hold line names a rollback");
    let words = bash_nullglob_words(&fx.proj, printed);
    assert_eq!(
        words,
        ["socket-patch", "rollback", PURL],
        "a shell passes the printed command on whole"
    );
    let mut argv: Vec<&str> = words[1..].iter().map(String::as_str).collect();
    argv.extend([
        "--json",
        "--cwd",
        cwd,
        "--api-url",
        &api,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        &api,
    ]);
    let (code, stdout, stderr) =
        run_socket_env(&fx.proj, &argv, &[("SOCKET_RUBYGEMS_URL", &upstream)]);
    assert_eq!(
        code, 0,
        "`{printed}`:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        String::from_utf8_lossy(&std::fs::read(&lock_path).unwrap()),
        String::from_utf8_lossy(&fx.pristine_lock),
        "`{printed}` hands the lock back byte for byte"
    );
    let (updated, update) = bundle_cold(&["update", DEP]);
    assert!(updated, "`bundle update {DEP}` after rollback:\n{update}");
    assert!(
        locked("1.1.0"),
        "after rollback `bundle update {DEP}` moves it to 1.1.0:\n{}",
        std::fs::read_to_string(&lock_path).unwrap()
    );
}

// ── precompiled platform gems ─────────────────────────────────────────
//
// The fixture gem as bundler locks a gem that ships precompiled platform
// gems (`vuln-gem (1.0.0-arm64-darwin)`), against a stand-in for the patch
// service that answers as the wire contract has it:
//
//   * the gem's fix is ONE patch, [`UUID`], the ruby gem's. Each patched
//     platform gem has a patch of its own ([`build_uuid`]), which the search
//     routes return beside the gem's and whose reference serves that gem
//     (`tarball`) and its stub gemspec;
//   * a reference request that carries `"gemBuilds": true` gets the gem
//     patch's registry under a snapshot URL (`…/<uuid>/s/<key>`) and the
//     list of the version's gems: the ruby gem, each patched platform gem
//     with its patch, each platform still on upstream's gem with none. A
//     request without it gets the plain URL and no list;
//   * the registry under a snapshot lists every gem of that list, serves
//     the file of a patched build, and answers the file of a platform with
//     none with a 302 to the upstream registry's own file: here a second
//     wiremock, the stand-in of that registry's file host, so nothing leaves
//     the machine. A platform whose build is still being made is in neither.
//     A snapshot answers as it did once a later one exists.
//
// "A machine of platform X" is this machine: bundler installs the platform
// gem of the host it runs on, so each case that turns on which platform is
// patched runs with this machine's platform in either role.

/// One build a compact index serves: its gem, the token the index lists it
/// under (`<version>` for the ruby gem, `<version>-<platform>` for a
/// platform gem), its runtime deps, and the `.gem` the download route
/// returns.
struct IndexBuild {
    name: &'static str,
    token: String,
    deps: Vec<String>,
    gem: Vec<u8>,
    /// Where the download route sends the client instead of serving `gem`,
    /// which the index still lists by its sha256.
    redirect: Option<String>,
}

/// [`mount_compact_index`] for gems published as several builds, the way
/// rubygems.org serves a gem with precompiled platform variants: one
/// `versions` line per gem listing every token, one `info/<name>` line and
/// one `gems/<name>-<token>.gem` route per build. `index_headers` go on
/// every index response.
async fn mount_build_index(
    server: &MockServer,
    base: &str,
    builds: &[IndexBuild],
    index_headers: &[(&str, &str)],
) {
    let index = |body: String| {
        let mut response = compact_index_body(body);
        for (name, value) in index_headers {
            response = response.insert_header(*name, *value);
        }
        response
    };
    let mut names: Vec<&str> = Vec::new();
    for build in builds {
        if !names.contains(&build.name) {
            names.push(build.name);
        }
    }
    let mut versions_body = String::from("created_at: 2026-01-01T00:00:00Z\n---\n");
    let mut names_body = String::from("---\n");
    for name in names {
        let mut info_body = String::from("---\n");
        let mut tokens: Vec<&str> = Vec::new();
        for build in builds.iter().filter(|build| build.name == name) {
            info_body.push_str(&format!(
                "{} {}|checksum:{}\n",
                build.token,
                build.deps.join(","),
                sha256_hex(&build.gem)
            ));
            tokens.push(&build.token);
            let file = match &build.redirect {
                Some(location) => ResponseTemplate::new(302)
                    .insert_header("Location", location.as_str())
                    .insert_header("Cache-Control", "no-store"),
                None => ResponseTemplate::new(200)
                    .set_body_raw(build.gem.clone(), "application/octet-stream"),
            };
            Mock::given(method("GET"))
                .and(path(format!("{base}/gems/{name}-{}.gem", build.token)))
                .respond_with(file)
                .mount(server)
                .await;
        }
        versions_body.push_str(&format!(
            "{name} {} {}\n",
            tokens.join(","),
            md5_hex(info_body.as_bytes())
        ));
        names_body.push_str(&format!("{name}\n"));
        Mock::given(method("GET"))
            .and(path(format!("{base}/info/{name}")))
            .respond_with(index(info_body))
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("{base}/versions")))
        .respond_with(index(versions_body))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/names")))
        .respond_with(index(names_body))
        .mount(server)
        .await;
}

/// `lib/vuln_gem.rb` of the platform fixture: [`orig_lib`] / [`patched_lib`]
/// plus a `require` of the build marker beside it.
fn build_marked(lib: String) -> String {
    lib.replace(
        "require \"tiny_dep\"\n",
        "require \"tiny_dep\"\nrequire \"vuln_gem/build\"\n",
    )
}

/// Author and `gem build` one build of the fixture gem: the ruby gem, or,
/// with `platform`, a platform gem. A platform gem needs no binary: a
/// pure-Ruby gem whose gemspec sets `s.platform` is one. Every build
/// carries the same `lib/vuln_gem.rb` (`lib`, the file the patch replaces)
/// and its own `lib/vuln_gem/build.rb`, which says which build Ruby loaded:
/// a real platform gem differs from the ruby gem only outside the patched
/// files, so one patch record's hashes hold for every build.
fn build_gem_build(stage: &Path, tag: &str, platform: Option<&str>, lib: &str) -> Vec<u8> {
    let build = platform.unwrap_or("ruby");
    let dir = stage.join(format!("{DEP}-{tag}-{build}-src"));
    std::fs::create_dir_all(dir.join("lib/vuln_gem")).unwrap();
    std::fs::write(dir.join("lib/vuln_gem.rb"), lib).unwrap();
    std::fs::write(
        dir.join("lib/vuln_gem/build.rb"),
        format!("module VulnGem\n  BUILD = \"{build}\"\nend\n"),
    )
    .unwrap();
    let platform_line = platform
        .map(|p| format!("  s.platform = \"{p}\"\n"))
        .unwrap_or_default();
    std::fs::write(
        dir.join(format!("{DEP}.gemspec")),
        format!(
            "Gem::Specification.new do |s|\n  s.name = \"{DEP}\"\n  s.version = \"{DEP_VERSION}\"\n{platform_line}  \
             s.summary = \"socket-patch hosted-gem platform fixture\"\n  s.authors = [\"socket-patch e2e\"]\n  \
             s.files = [\"lib/vuln_gem.rb\", \"lib/vuln_gem/build.rb\"]\n  s.require_paths = [\"lib\"]\n  \
             s.add_dependency \"{TRANSITIVE}\", \">= 0\"\nend\n"
        ),
    )
    .unwrap();
    let mut cmd = Command::new("gem");
    cmd.args(["build", &format!("{DEP}.gemspec")])
        .current_dir(&dir);
    cache_env::isolate(&mut cmd);
    let out = cmd.output().expect("failed to run gem build");
    assert!(
        out.status.success(),
        "gem build {DEP} ({build}) failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let leaf = match platform {
        Some(p) => format!("{DEP}-{DEP_VERSION}-{p}"),
        None => format!("{DEP}-{DEP_VERSION}"),
    };
    std::fs::read(dir.join(format!("{leaf}.gem")))
        .unwrap_or_else(|e| panic!("built {leaf}.gem: {e}"))
}

/// The platform of this machine's precompiled gems as their file names and
/// `Gemfile.lock` spell it (`arm64-darwin`, `x86_64-linux`): the local
/// platform without its OS version, which a gem built for it matches on
/// every release of the OS. With it, a platform this machine is not.
fn own_and_foreign_platform() -> (String, String) {
    let mut ruby = Command::new("ruby");
    ruby.args([
        "-e",
        "p = Gem::Platform.local; print [p.cpu, p.os].join(\"-\")",
    ]);
    cache_env::isolate(&mut ruby);
    let out = ruby.output().expect("failed to run ruby");
    assert!(out.status.success(), "local platform probe failed");
    let own = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let foreign = if own.ends_with("-linux") {
        "arm64-darwin"
    } else {
        "x86_64-linux"
    };
    (own, foreign.to_string())
}

/// Shaped like a Socket API token, so that no run warns about the token
/// itself and a case can hold a run's warnings to an exact list.
const API_TOKEN: &str = "sktsec_00000000000000000000000000000000000000000000_api";

/// How the patch service has one platform gem of the fixture gem's version.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Has {
    /// A patched build, under a patch of its own.
    Patched,
    /// No patched build yet: the registry lists upstream's own gem and
    /// answers its file with a redirect to the upstream registry.
    Upstream,
    /// A patched build is being made: no list names the platform yet.
    Building,
}

/// The uuid of the patch of `platform`'s patched build.
fn build_uuid(platform: &str) -> String {
    let hex = sha256_hex(format!("{UUID}/{platform}").as_bytes());
    format!(
        "{}-{}-4{}-8{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    )
}

/// A build's token in the lock, the compact index and its file name:
/// `<version>` for the ruby gem, `<version>-<platform>` for a platform gem.
fn build_token(platform: Option<&str>) -> String {
    match platform {
        Some(platform) => format!("{DEP_VERSION}-{platform}"),
        None => DEP_VERSION.to_string(),
    }
}

/// The purl of a platform gem, as a run reports it and as its own patch's
/// record names it.
fn platform_purl(platform: &str) -> String {
    format!("{PURL}?platform={platform}")
}

/// One gem of the version as the registry lists it.
struct ListedGem {
    /// `None`: the ruby gem.
    platform: Option<String>,
    /// The sha256 of the archive the registry serves for it.
    sha256: String,
    /// The patch of its patched build; `None`: upstream's own gem.
    patch: Option<String>,
}

/// The key of the registry snapshot that lists `listed`: derived from the
/// list, so that the same list is the same URL.
fn snapshot_key(listed: &[ListedGem]) -> String {
    let text: String = listed
        .iter()
        .map(|gem| {
            format!(
                "{} {} {}\n",
                gem.platform.as_deref().unwrap_or("ruby"),
                gem.sha256,
                gem.patch.as_deref().unwrap_or("-")
            )
        })
        .collect();
    sha256_hex(text.as_bytes())[..12].to_string()
}

/// What the stand-in patch service answers from: the gems, and how it has
/// each platform gem now.
struct PlatformService {
    /// The origin of the wiremock that plays the patch service.
    api: String,
    /// The origin of the stand-in of the upstream registry's file host.
    files: String,
    /// `lib/vuln_gem.rb` before and after the patch.
    orig: String,
    patched: String,
    /// Upstream's gems, the patched builds and the stub gemspecs of the
    /// patched builds, each by [`build_token`].
    upstream: std::collections::BTreeMap<String, Vec<u8>>,
    builds: std::collections::BTreeMap<String, Vec<u8>>,
    stubs: std::collections::BTreeMap<String, Vec<u8>>,
    /// How the service has each platform gem; `None`: it has no list for
    /// the gem (a patch of the ruby gem alone).
    listing: std::sync::Mutex<Option<Vec<(String, Has)>>>,
}

impl PlatformService {
    /// The sha256 of the gem of `platform`: its patched build, or
    /// upstream's own.
    fn sha(&self, platform: Option<&str>, patched: bool) -> String {
        let gems = if patched {
            &self.builds
        } else {
            &self.upstream
        };
        sha256_hex(&gems[&build_token(platform)])
    }

    /// What the registry lists now: the patched ruby gem, then each
    /// platform gem that is patched or on upstream's gem.
    fn listed(&self) -> Option<Vec<ListedGem>> {
        let listing = self.listing.lock().unwrap().clone()?;
        let mut listed = vec![ListedGem {
            platform: None,
            sha256: self.sha(None, true),
            patch: Some(UUID.to_string()),
        }];
        for (platform, has) in listing {
            let patched = match has {
                Has::Patched => true,
                Has::Upstream => false,
                Has::Building => continue,
            };
            listed.push(ListedGem {
                sha256: self.sha(Some(&platform), patched),
                patch: patched.then(|| build_uuid(&platform)),
                platform: Some(platform),
            });
        }
        Some(listed)
    }

    /// The patches a search finds for the gem, as `(uuid, purl)`: the gem's
    /// own, and the patch of each patched platform gem.
    fn found(&self) -> Vec<(String, String)> {
        let mut found = vec![(UUID.to_string(), PURL.to_string())];
        for gem in self.listed().unwrap_or_default() {
            if let (Some(platform), Some(patch)) = (gem.platform, gem.patch) {
                found.push((patch, platform_purl(&platform)));
            }
        }
        found
    }

    /// The path the artifact `leaf` of the patch `uuid` is served at.
    fn artifact_path(uuid: &str, leaf: &str) -> String {
        format!("/patch/gem/{DEP}/{DEP_VERSION}/{TOKEN}/{uuid}/{leaf}")
    }

    /// The artifacts of the patch `uuid` of the gem of `platform`: the
    /// patched gem and its stub gemspec.
    fn artifacts(&self, uuid: &str, platform: Option<&str>) -> serde_json::Value {
        let token = build_token(platform);
        let (gem, stub) = (&self.builds[&token], &self.stubs[&token]);
        let url = |ext: &str| {
            let leaf = format!("{DEP}-{token}.{ext}");
            format!("{}{}", self.api, Self::artifact_path(uuid, &leaf))
        };
        serde_json::json!([
            { "kind": "tarball", "url": url("gem"),
              "integrity": { "sha512": sri(gem), "sha256": sha256_hex(gem) } },
            { "kind": "gem-stub-gemspec", "url": url("gemspec"),
              "integrity": { "sha512": sri(stub) } },
        ])
    }

    /// The reference of the gem's patch. `with_list`: the request asked for
    /// the list of the gem's builds.
    fn gem_reference(&self, with_list: bool) -> serde_json::Value {
        let mut identifiers = serde_json::json!({
            "name": DEP,
            "version": DEP_VERSION,
            "gemChecksumSha256": self.sha(None, true),
        });
        let mut index_url = format!("{}/patch-registry/gem/{TOKEN}/{UUID}/", self.api);
        if let Some(listed) = self.listed().filter(|_| with_list) {
            index_url = format!("{index_url}s/{}", snapshot_key(&listed));
            let mut builds: Vec<serde_json::Value> = listed
                .iter()
                .map(|gem| {
                    serde_json::json!({
                        "platform": gem.platform.as_deref().unwrap_or("ruby"),
                        "gemChecksumSha256": gem.sha256,
                        "patchUuid": gem.patch,
                    })
                })
                .collect();
            builds.sort_by_key(|build| build["platform"].as_str().map(str::to_string));
            identifiers["gemBuilds"] = builds.into();
        }
        let artifacts = self.artifacts(UUID, None);
        serde_json::json!({
            "status": "granted",
            "url": artifacts[0]["url"],
            "purl": PURL,
            "artifacts": artifacts,
            "registryOverride": {
                "kind": "rubygems-compact-index",
                "indexUrl": index_url,
                "identifiers": identifiers,
            }
        })
    }

    /// The answer to one package reference request: every uuid it names
    /// that is a patch here.
    fn references(&self, request: &wiremock::Request) -> ResponseTemplate {
        let asked: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let with_list = asked["gemBuilds"] == true;
        let found = self.found();
        let mut results = serde_json::Map::new();
        for uuid in asked["uuids"].as_array().into_iter().flatten() {
            let Some(uuid) = uuid.as_str() else { continue };
            let Some((_, purl)) = found.iter().find(|(patch, _)| patch == uuid) else {
                continue;
            };
            let reference = match purl.split_once("?platform=") {
                None => self.gem_reference(with_list),
                Some((_, platform)) => {
                    let artifacts = self.artifacts(uuid, Some(platform));
                    serde_json::json!({
                        "status": "granted",
                        "url": artifacts[0]["url"],
                        "purl": purl,
                        "artifacts": artifacts,
                    })
                }
            };
            results.insert(uuid.to_string(), reference);
        }
        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
    }

    /// The record of the patch `uuid` of `purl`: every build carries the
    /// one patched file.
    fn view(&self, uuid: &str, purl: &str) -> serde_json::Value {
        serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "lib/vuln_gem.rb": {
                    "beforeHash": compute_git_sha256_from_bytes(self.orig.as_bytes()),
                    "afterHash": compute_git_sha256_from_bytes(self.patched.as_bytes()),
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
        })
    }

    /// Mount the patches API, the artifacts of every patch, and the gem
    /// patch's registry under its plain URL, which lists the patched ruby
    /// gem alone.
    async fn mount(self: &std::sync::Arc<Self>, server: &MockServer) {
        let api = format!("/v0/orgs/{ORG}/patches");
        let service = self.clone();
        Mock::given(method("POST"))
            .and(path(format!("{api}/batch")))
            .respond_with(move |_: &wiremock::Request| {
                let patches: Vec<serde_json::Value> = service
                    .found()
                    .iter()
                    .map(|(uuid, purl)| {
                        serde_json::json!({
                            "uuid": uuid, "purl": purl, "tier": "free",
                            "cveIds": [], "ghsaIds": [], "severity": "high",
                            "title": "gem platform capstone fixture"
                        })
                    })
                    .collect();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "packages": [{ "purl": PURL, "patches": patches }],
                    "canAccessPaidPatches": false,
                }))
            })
            .mount(server)
            .await;
        // A platform gem's patch is published after the gem's: a search
        // ranks it first.
        let service = self.clone();
        Mock::given(method("GET"))
            .and(path_regex(format!("^{api}/by-package/.+$")))
            .respond_with(move |_: &wiremock::Request| {
                let patches: Vec<serde_json::Value> = service
                    .found()
                    .iter()
                    .rev()
                    .map(|(uuid, purl)| {
                        let published = match uuid.as_str() {
                            UUID => "2026-01-01T00:00:00Z",
                            _ => "2026-02-01T00:00:00Z",
                        };
                        serde_json::json!({
                            "uuid": uuid, "purl": purl, "publishedAt": published,
                            "description": "x", "license": "MIT", "tier": "free",
                            "vulnerabilities": {}
                        })
                    })
                    .collect();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "patches": patches,
                    "canAccessPaidPatches": false,
                }))
            })
            .mount(server)
            .await;
        let service = self.clone();
        Mock::given(method("POST"))
            .and(path(format!("{api}/package")))
            .respond_with(move |request: &wiremock::Request| service.references(request))
            .mount(server)
            .await;
        for token in self.builds.keys() {
            let platform = token.strip_prefix(&format!("{DEP_VERSION}-"));
            let (uuid, purl) = match platform {
                Some(platform) => (build_uuid(platform), platform_purl(platform)),
                None => (UUID.to_string(), PURL.to_string()),
            };
            Mock::given(method("GET"))
                .and(path(format!("{api}/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(self.view(&uuid, &purl)))
                .mount(server)
                .await;
            for (ext, bytes) in [
                ("gem", &self.builds[token]),
                ("gemspec", &self.stubs[token]),
            ] {
                let leaf = format!("{DEP}-{token}.{ext}");
                Mock::given(method("GET"))
                    .and(path(Self::artifact_path(&uuid, &leaf)))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
                    .mount(server)
                    .await;
            }
        }
        let ruby_gem = IndexBuild {
            name: DEP,
            token: build_token(None),
            deps: vec![format!("{TRANSITIVE}:>= 0")],
            gem: self.builds[&build_token(None)].clone(),
            redirect: None,
        };
        let plain = format!("/patch-registry/gem/{TOKEN}/{UUID}");
        mount_build_index(server, &plain, &[ruby_gem], REGISTRY_INDEX_HEADERS).await;
    }
}

/// What the patch registry sends with every index response.
const REGISTRY_INDEX_HEADERS: &[(&str, &str)] = &[("Cache-Control", "public, no-cache")];

/// A project the real bundler locked to the fixture gem's platform gems of
/// this machine's platform ([`Self::own`]) and of one it is not
/// ([`Self::foreign`]) and installed, with the stand-in patch service.
struct PlatformProject {
    /// The project, its pair before any scan, and the wiremock that plays
    /// the upstream registry, the patch registry and the patches API.
    /// `index_url` is the registry of the listing served last.
    fx: RedirectFixture,
    /// The stand-in of the upstream registry's file host: where the patch
    /// registry sends a client for a platform it has no patched build of.
    files: MockServer,
    service: std::sync::Arc<PlatformService>,
    /// The registry snapshots mounted so far, by path.
    snapshots: std::collections::BTreeSet<String>,
    own: String,
    foreign: String,
    /// The lock has a `CHECKSUMS` section.
    checksums: bool,
}

impl PlatformProject {
    /// Build the gems, start both servers, and let the real bundler lock
    /// and install the project. Upstream publishes the gem as a ruby gem
    /// and as platform gems for this machine's platform, a foreign one and
    /// each of `more`; the lock names the first two. `ruby_entry` picks the
    /// lock's PLATFORMS: without `ruby` the lock holds the platform builds
    /// alone, with it bundler keeps the ruby-platform `name (version)`
    /// entry beside them (what bundler 4 locks by default for a gem that
    /// also ships a ruby gem). `None`: the bundler is below `floor` or
    /// missing (said on stdout).
    async fn start(
        tag: &str,
        floor: (u32, u32),
        checksums: bool,
        ruby_entry: bool,
        more: &[&str],
    ) -> Option<PlatformProject> {
        let bundler = bundler_e2e::gate("e2e_redirect_gem_build", tag, floor, &|c| {
            cache_env::isolate(c);
        })?;
        let (own, foreign) = own_and_foreign_platform();
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join("gem-stage");
        let (orig, patched) = (build_marked(orig_lib()), build_marked(patched_lib()));
        let platforms = [own.as_str(), foreign.as_str()];
        let published = std::iter::once(None)
            .chain(platforms.into_iter().map(Some))
            .chain(more.iter().copied().map(Some));
        let mut upstream = std::collections::BTreeMap::new();
        let mut builds = std::collections::BTreeMap::new();
        let mut stubs = std::collections::BTreeMap::new();
        for platform in published {
            let token = build_token(platform);
            upstream.insert(
                token.clone(),
                build_gem_build(&stage, "orig", platform, &orig),
            );
            let build = build_gem_build(&stage, "patched", platform, &patched);
            stubs.insert(token.clone(), stub_gemspec(&build));
            builds.insert(token, build);
        }

        let server = MockServer::start().await;
        let files = MockServer::start().await;
        let mut index: Vec<IndexBuild> = upstream
            .iter()
            .map(|(token, gem)| IndexBuild {
                name: DEP,
                token: token.clone(),
                deps: vec![format!("{TRANSITIVE}:>= 0")],
                gem: gem.clone(),
                redirect: None,
            })
            .collect();
        index.push(IndexBuild {
            name: TRANSITIVE,
            token: "1.0.0".to_string(),
            deps: vec![],
            gem: build_gem(&stage, TRANSITIVE, "1.0.0", "tiny_dep.rb", TINY_LIB, &[]),
            redirect: None,
        });
        mount_build_index(&server, "/upstream", &index, &[]).await;
        for (token, gem) in &upstream {
            Mock::given(method("GET"))
                .and(path(format!("/gems/{DEP}-{token}.gem")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(gem.clone(), "application/octet-stream"),
                )
                .mount(&files)
                .await;
        }
        let service = std::sync::Arc::new(PlatformService {
            api: server.uri(),
            files: files.uri(),
            orig: orig.clone(),
            patched: patched.clone(),
            upstream,
            builds,
            stubs,
            listing: std::sync::Mutex::new(None),
        });
        service.mount(&server).await;

        // The project, locked and installed by the real bundler.
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("Gemfile"),
            format!("source \"{}/upstream\"\n\ngem \"{DEP}\"\n", server.uri()),
        )
        .unwrap();
        let config_args = bundler.config_local_args("path", "vendor/bundle");
        let config_args: Vec<&str> = config_args.iter().map(String::as_str).collect();
        bundle_ok(&proj, &config_args);
        if !checksums && bundler.at_least(2, 6) {
            bundle_ok(
                &proj,
                &["config", "set", "--local", "lockfile_checksums", "false"],
            );
        }
        bundle_ok(&proj, &["install"]);
        bundle_ok(&proj, &["lock", "--add-platform", &foreign]);
        // Bundler adds platforms by itself to a lock it creates (4.0.15
        // does): `ruby` when every locked gem has a ruby-platform gem, and
        // the common platforms every locked gem has a gem for. Pin the
        // shape either way.
        let locks = |platform: &str| {
            let lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
            let platforms = lock.split("\nPLATFORMS\n").nth(1).unwrap_or_default();
            let platforms = platforms.split("\n\n").next().unwrap_or_default();
            platforms.lines().any(|line| line.trim() == platform)
        };
        if ruby_entry && !locks("ruby") {
            bundle_ok(&proj, &["lock", "--add-platform", "ruby"]);
        } else if !ruby_entry && locks("ruby") {
            bundle_ok(&proj, &["lock", "--remove-platform", "ruby"]);
        }
        for platform in more {
            if locks(platform) {
                bundle_ok(&proj, &["lock", "--remove-platform", platform]);
            }
        }
        if checksums {
            bundle_ok(&proj, &["lock", "--add-checksums"]);
        }
        let pristine_gemfile = std::fs::read(proj.join("Gemfile")).unwrap();
        let pristine_lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
        for platform in platforms {
            assert!(
                pristine_lock.contains(&format!("    {DEP} ({})\n", build_token(Some(platform)))),
                "the fixture lock must pin the {platform} build:\n{pristine_lock}"
            );
        }
        assert_eq!(
            pristine_lock.contains(&format!("    {DEP} ({DEP_VERSION})\n")),
            ruby_entry,
            "the fixture lock's ruby-platform entry must match the case:\n{pristine_lock}"
        );
        assert_eq!(
            pristine_lock.matches(&format!("    {DEP} (")).count(),
            2 + usize::from(ruby_entry),
            "the fixture lock must name no other build:\n{pristine_lock}"
        );
        assert_eq!(
            pristine_lock.contains("\nCHECKSUMS\n"),
            checksums,
            "fixture lock CHECKSUMS presence must match the case:\n{pristine_lock}"
        );
        let project = PlatformProject {
            fx: RedirectFixture {
                tmp,
                proj,
                index_url: String::new(),
                gemfile_name: "Gemfile",
                lock_name: "Gemfile.lock",
                patched: patched.into_bytes(),
                pristine_gemfile,
                pristine_lock: pristine_lock.into_bytes(),
                bundler,
                _server: server,
            },
            files,
            service,
            snapshots: std::collections::BTreeSet::new(),
            own,
            foreign,
            checksums,
        };
        assert_eq!(
            std::fs::read_to_string(project.installed_lib(&project.fx.proj))
                .expect("bundler installed the platform gem"),
            orig,
            "premise: the upstream platform gem is installed before the scan"
        );
        Some(project)
    }

    fn api(&self) -> String {
        self.fx._server.uri()
    }

    fn pristine_lock(&self) -> String {
        String::from_utf8(self.fx.pristine_lock.clone()).unwrap()
    }

    fn pristine_gemfile(&self) -> String {
        String::from_utf8(self.fx.pristine_gemfile.clone()).unwrap()
    }

    fn lock(&self) -> String {
        std::fs::read_to_string(self.fx.proj.join("Gemfile.lock")).unwrap()
    }

    fn gemfile(&self) -> String {
        std::fs::read_to_string(self.fx.proj.join("Gemfile")).unwrap()
    }

    /// `<name>-<version>-<platform>` of this machine's platform gem.
    fn own_leaf(&self) -> String {
        format!("{DEP}-{}", build_token(Some(&self.own)))
    }

    /// `lib/vuln_gem.rb` of this machine's platform gem as bundler
    /// installed it under `dir`.
    fn installed_lib(&self, dir: &Path) -> PathBuf {
        fresh_installed_lib(dir, &self.own_leaf(), "vuln_gem.rb")
    }

    /// From now on the service has the platform gems as `listing` says
    /// (`None`: it has no list for the gem), and its registry answers under
    /// the snapshot of that listing beside every earlier one. Returns the
    /// registry URL as a lock names it.
    async fn serve(&mut self, listing: Option<&[(&str, Has)]>) -> String {
        *self.service.listing.lock().unwrap() = listing.map(|listing| {
            listing
                .iter()
                .map(|(platform, has)| (platform.to_string(), *has))
                .collect()
        });
        let mut base = format!("/patch-registry/gem/{TOKEN}/{UUID}");
        if let Some(listed) = self.service.listed() {
            base = format!("{base}/s/{}", snapshot_key(&listed));
            if self.snapshots.insert(base.clone()) {
                let index: Vec<IndexBuild> = listed
                    .iter()
                    .map(|gem| {
                        let token = build_token(gem.platform.as_deref());
                        let (gems, redirect) = match gem.patch {
                            Some(_) => (&self.service.builds, None),
                            None => (
                                &self.service.upstream,
                                Some(format!("{}/gems/{DEP}-{token}.gem", self.service.files)),
                            ),
                        };
                        IndexBuild {
                            name: DEP,
                            deps: vec![format!("{TRANSITIVE}:>= 0")],
                            gem: gems[&token].clone(),
                            token,
                            redirect,
                        }
                    })
                    .collect();
                mount_build_index(&self.fx._server, &base, &index, REGISTRY_INDEX_HEADERS).await;
            }
        }
        self.fx.index_url = format!("{}{base}/", self.api());
        self.fx.index_url.clone()
    }

    /// `socket-patch <command…> --mode hosted` over `dir` against the
    /// stand-in service, with `extra` arguments.
    fn hosted(&self, dir: &Path, command: &[&str], extra: &[&str]) -> (i32, String, String) {
        let api = self.api();
        let mut args: Vec<&str> = command.to_vec();
        args.extend([
            "--mode",
            "hosted",
            "--yes",
            "--cwd",
            dir.to_str().expect("utf8 tmp path"),
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            API_TOKEN,
        ]);
        args.extend_from_slice(extra);
        run_socket(dir, &args)
    }

    /// A `--json` hosted scan of the project, which must exit 0: its
    /// envelope.
    fn scan(&self, extra: &[&str]) -> serde_json::Value {
        let mut args = vec!["--json"];
        args.extend_from_slice(extra);
        let (code, stdout, stderr) = self.hosted(&self.fx.proj, &["scan"], &args);
        assert_eq!(
            code, 0,
            "scan failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("scan --json is not JSON: {e}\nstdout:\n{stdout}"))
    }

    /// A scan that leaves the gem where it is, quietly: exit 0, both files
    /// byte-identical, no warning, and one counted `skipped` event under
    /// `code` whose reason is `line`; a person reads that one line on
    /// stdout, and nothing on stderr warns or names the gem. The copy
    /// bundler installed stays upstream's.
    fn assert_left_alone(&self, code: &str, line: &str) {
        let untouched = |when: &str| {
            assert_eq!(self.lock(), self.pristine_lock(), "{when}: the lock");
            assert_eq!(
                self.gemfile(),
                self.pristine_gemfile(),
                "{when}: the Gemfile"
            );
            assert_eq!(
                std::fs::read_to_string(self.installed_lib(&self.fx.proj)).unwrap(),
                self.service.orig,
                "{when}: the installed copy"
            );
        };
        let env = self.scan(&[]);
        assert_eq!(env["status"], "success", "{env}");
        assert_eq!(
            hosted_events(&env),
            [serde_json::json!({
                "action": "skipped", "purl": PURL, "uuid": UUID,
                "errorCode": code, "reason": line,
                "details": { "mode": "hosted" },
            })],
            "{env}"
        );
        assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
        let summary = &env["summary"];
        assert_eq!(
            (&summary["applied"], &summary["skipped"], &summary["failed"]),
            (
                &serde_json::json!(0),
                &serde_json::json!(1),
                &serde_json::json!(0)
            ),
            "{env}"
        );
        assert_eq!(env["redirect"]["rewrittenFiles"], serde_json::json!([]));
        untouched("--json");

        let (code, stdout, stderr) = self.hosted(&self.fx.proj, &["scan"], &[]);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        assert!(stdout.contains(&format!("\n{line}\n")), "{stdout}");
        assert!(
            !stderr.contains("No patches could be switched")
                && !stderr.contains("Warning")
                && !stderr.contains(DEP),
            "nothing on stderr names it:\n{stderr}"
        );
        untouched("for a person");
    }

    /// The project's pair as a hosted scan must leave it for the registry
    /// `index_url`, where `pinned` says of each locked platform whether its
    /// patched build is what the lock pins: the Gemfile's declaration with
    /// the `source:` option, every build of the gem under the registry's
    /// `GEM` section and none upstream, each `CHECKSUMS` entry on the sha256
    /// the registry serves for it, and `DEPENDENCIES` source-pinned.
    /// Returns the lock.
    fn assert_hosted_pair(&self, index_url: &str, pinned: &[(&str, bool)]) -> String {
        assert_eq!(
            self.gemfile(),
            with_source_option(
                &self.pristine_gemfile(),
                &format!("gem \"{DEP}\""),
                index_url
            ),
            "the Gemfile edit is the one a ruby gem gets"
        );
        let lock = self.lock();
        let registry_section = lock
            .split("\n\n")
            .find(|section| section.contains(&format!("remote: {index_url}\n")))
            .unwrap_or_else(|| panic!("no GEM section of {index_url}:\n{lock}"));
        let pristine = self.pristine_lock();
        for (platform, patched) in pinned {
            let token = build_token(Some(platform));
            assert!(
                registry_section.contains(&format!("    {DEP} ({token})\n      {TRANSITIVE}")),
                "the {platform} build is under the patch registry with its sub-lines:\n{lock}"
            );
            if self.checksums {
                let pin = format!(
                    "  {DEP} ({token}) sha256={}\n",
                    self.service.sha(Some(platform), *patched)
                );
                assert!(
                    lock.contains(&pin),
                    "CHECKSUMS pins the {platform} build to the sha256 the registry serves for \
                     it (patched: {patched}):\n{lock}"
                );
                assert_eq!(
                    pristine.contains(&pin),
                    !*patched,
                    "a build on upstream's gem keeps the sha256 it had, a patched one does not"
                );
            }
        }
        let entries = |text: &str| text.matches(&format!("    {DEP} (")).count();
        assert_eq!(
            entries(&lock),
            entries(&pristine),
            "every build, each listed once:\n{lock}"
        );
        assert_eq!(
            entries(registry_section),
            entries(&lock),
            "all of them under the patch registry:\n{lock}"
        );
        if self.checksums && pristine.contains(&format!("    {DEP} ({DEP_VERSION})\n")) {
            let ruby_sha = self.service.sha(None, true);
            assert!(
                lock.contains(&format!("  {DEP} ({DEP_VERSION}) sha256={ruby_sha}\n")),
                "CHECKSUMS pins the ruby-platform entry to the patched ruby gem:\n{lock}"
            );
        }
        assert!(
            lock.contains(&format!("\nDEPENDENCIES\n  {DEP}!\n")),
            "DEPENDENCIES is source-pinned:\n{lock}"
        );
        lock
    }

    /// The lock the host bundler itself writes for `gemfile` over the lock
    /// `before`, in a scratch dir named `name`.
    fn bundler_lock(&self, name: &str, gemfile: &str, before: &str) -> String {
        let relock = self.fx.tmp.path().join(name);
        std::fs::create_dir_all(&relock).unwrap();
        std::fs::write(relock.join("Gemfile"), gemfile).unwrap();
        std::fs::write(relock.join("Gemfile.lock"), before).unwrap();
        copy_dir_recursive(&self.fx.proj.join(".bundle"), &relock.join(".bundle"));
        bundle_ok(&relock, &["lock"]);
        std::fs::read_to_string(relock.join("Gemfile.lock")).unwrap()
    }

    /// A fresh checkout of the committed pair, named `name`, after the
    /// real `bundle install` with `envs` succeeded there and left the lock
    /// byte-identical.
    fn install_fresh(&self, name: &str, envs: &[(&str, &str)]) -> PathBuf {
        let fresh = stage_fresh_checkout(&self.fx, name);
        let install = bundle_env(&fresh, &["install"], envs);
        assert!(
            install.status.success(),
            "`bundle install` ({envs:?}) of a fresh checkout must succeed.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&install.stdout),
            String::from_utf8_lossy(&install.stderr),
        );
        assert_eq!(
            std::fs::read_to_string(fresh.join("Gemfile.lock")).unwrap(),
            self.lock(),
            "`bundle install` ({envs:?}) must leave the lock byte-identical (bundler {})",
            self.fx.bundler.version
        );
        fresh
    }

    /// `dir` holds this machine's platform gem, the patched build or
    /// upstream's own as `patched` says, never the ruby gem, and Ruby loads
    /// that file from that platform gem.
    fn assert_installed(&self, dir: &Path, patched: bool) {
        let (lib, status) = if patched {
            (&self.service.patched, patched_marker())
        } else {
            (&self.service.orig, "VULNERABLE".to_string())
        };
        assert_eq!(
            &std::fs::read_to_string(self.installed_lib(dir))
                .expect("the platform gem is installed"),
            lib,
            "the install holds the file of the {} platform gem",
            if patched { "patched" } else { "upstream" }
        );
        assert!(
            !fresh_installed_lib(dir, &format!("{DEP}-{DEP_VERSION}"), "vuln_gem.rb").exists(),
            "the ruby-platform gem is not what bundler installs"
        );
        let probe = bundle(
            dir,
            &[
                "exec",
                "ruby",
                "-e",
                "require \"vuln_gem\"\nputs VulnGem.status\nputs VulnGem::BUILD\nputs TinyDep::VALUE\nputs $LOADED_FEATURES.grep(%r{/vuln_gem\\.rb\\z})",
            ],
        );
        assert!(
            probe.status.success(),
            "bundle exec require probe failed.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&probe.stdout),
            String::from_utf8_lossy(&probe.stderr),
        );
        let out = String::from_utf8_lossy(&probe.stdout).into_owned();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            4,
            "status, build, dep and the loaded file:\n{out}"
        );
        assert_eq!(
            lines[..3],
            [status.as_str(), self.own.as_str(), "tiny-ok"],
            "Ruby loads that file, from this machine's platform build:\n{out}"
        );
        assert!(
            lines[3].contains("/vendor/bundle/")
                && lines[3].contains(&format!("/gems/{}/lib/", self.own_leaf())),
            "vuln_gem.rb loads from the installed platform gem:\n{out}"
        );
    }

    /// How many requests the patch service and the upstream file host have
    /// answered: a mark for [`Self::fetched_since`].
    async fn mark(&self) -> (usize, usize) {
        (
            request_paths(&self.fx._server, 0).await.len(),
            request_paths(&self.files, 0).await.len(),
        )
    }

    /// The gem files asked for since `mark`: of the patch registry (each
    /// with the snapshot path it was asked under), and of the upstream file
    /// host.
    async fn fetched_since(&self, mark: (usize, usize)) -> (Vec<String>, Vec<String>) {
        let registry = request_paths(&self.fx._server, mark.0)
            .await
            .into_iter()
            .filter(|path| path.starts_with("/patch-registry/") && path.contains("/gems/"))
            .collect();
        let files = request_paths(&self.files, mark.1)
            .await
            .into_iter()
            .filter_map(|path| path.strip_prefix("/gems/").map(str::to_string))
            .collect();
        (registry, files)
    }

    /// The body of every package reference request since `mark`, after
    /// asserting that each asked for the list of the gem's builds.
    async fn references_since(&self, mark: (usize, usize)) -> Vec<Vec<String>> {
        let requests = self.fx._server.received_requests().await;
        let mut asked = Vec::new();
        for request in requests.unwrap_or_default().iter().skip(mark.0) {
            if !request.url.path().ends_with("/patches/package") {
                continue;
            }
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
            assert_eq!(
                body["gemBuilds"], true,
                "every package reference request asks for the list of the gem's builds: {body}"
            );
            let uuids = body["uuids"].as_array().into_iter().flatten();
            asked.push(
                uuids
                    .filter_map(|uuid| uuid.as_str().map(str::to_string))
                    .collect(),
            );
        }
        asked
    }

    /// The patch records fetched since `mark`, by uuid.
    async fn views_since(&self, mark: (usize, usize)) -> Vec<String> {
        let requests = self.fx._server.received_requests().await;
        let requests = requests.unwrap_or_default();
        let paths = requests.iter().skip(mark.0).map(|r| r.url.path());
        paths
            .filter_map(|path| path.rsplit_once("/patches/view/"))
            .map(|(_, uuid)| uuid.to_string())
            .collect()
    }

    /// `text` with the mock upstream spelled as rubygems.org on a
    /// `CHECKSUMS` lock: an unwind re-derives a `CHECKSUMS` sha256 only for
    /// a rubygems.org remote, so there the pair names that registry and the
    /// mock serves it (`SOCKET_RUBYGEMS_URL`).
    fn as_committed(&self, text: &str) -> String {
        let upstream = format!("{}/upstream", self.api());
        if self.checksums {
            text.replace(&format!("\"{upstream}\""), "\"https://rubygems.org\"")
                .replace(&format!("{upstream}/"), "https://rubygems.org/")
        } else {
            text.to_string()
        }
    }

    /// Spell the project's pair as [`Self::as_committed`] does. No bundler
    /// runs on a `CHECKSUMS` project after this.
    fn commit_pair(&self) {
        for file in ["Gemfile", "Gemfile.lock"] {
            let path = self.fx.proj.join(file);
            let text = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, self.as_committed(&text)).unwrap();
        }
    }

    /// `socket-patch <argv…> --json` over `dir` as an unwind runs: against
    /// the stand-in service, which is also the patch server, with the mock
    /// upstream as the gem registry. Returns the exit code, stdout, stderr.
    fn unwind(&self, dir: &Path, argv: &[&str]) -> (i32, String, String) {
        let api = self.api();
        let upstream = format!("{api}/upstream");
        let mut args: Vec<&str> = argv.to_vec();
        args.extend([
            "--json",
            "--cwd",
            dir.to_str().expect("utf8 tmp path"),
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            API_TOKEN,
            "--patch-server-url",
            &api,
        ]);
        run_socket_env(dir, &args, &[("SOCKET_RUBYGEMS_URL", &upstream)])
    }

    /// `rollback` of the gem: the pair before any scan, byte for byte.
    /// Returns the run's stdout.
    fn roll_back(&self) -> String {
        self.commit_pair();
        let (code, stdout, stderr) = self.unwind(&self.fx.proj, &["rollback", PURL]);
        assert_eq!(code, 0, "rollback:\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert_eq!(
            self.lock(),
            self.as_committed(&self.pristine_lock()),
            "rollback must hand the lock back byte for byte"
        );
        assert_eq!(
            self.gemfile(),
            self.as_committed(&self.pristine_gemfile()),
            "rollback must hand the Gemfile back byte for byte"
        );
        stdout
    }
}

/// The path of every request `server` has answered, after the first `skip`.
async fn request_paths(server: &MockServer, skip: usize) -> Vec<String> {
    let requests = server.received_requests().await.unwrap_or_default();
    let paths = requests.iter().skip(skip);
    paths
        .map(|request| request.url.path().to_string())
        .collect()
}

/// `bundle <args>` in `dir`, which must succeed.
fn bundle_ok(dir: &Path, args: &[&str]) {
    let out = bundle(dir, args);
    assert!(
        out.status.success(),
        "bundle {args:?} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// The hosted events of a run (`details.mode: "hosted"`), by the platform
/// they name (the ruby gem's, which names none, first).
fn hosted_events(env: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut events: Vec<serde_json::Value> = env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| event["details"]["mode"] == "hosted")
        .cloned()
        .collect();
    events.sort_by_key(|event| {
        let platform = event["details"]["platform"].as_str();
        platform.map(str::to_string)
    });
    events
}

/// The warning codes of a run, in envelope order.
fn warning_codes(env: &serde_json::Value) -> Vec<String> {
    let warnings = env["warnings"].as_array().into_iter().flatten();
    warnings
        .map(|w| w["code"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The event of a patched build: `applied`, under the build's own patch,
/// with `newlyPatched` when the run put the build in place.
fn patched_event(platform: &str, newly: bool) -> serde_json::Value {
    let mut details = serde_json::json!({ "gemFix": UUID, "platform": platform, "mode": "hosted" });
    if newly {
        details["newlyPatched"] = serde_json::json!(true);
    }
    serde_json::json!({
        "action": "applied", "purl": platform_purl(platform), "uuid": build_uuid(platform),
        "details": details,
    })
}

/// The event of the ruby-platform entry a lock keeps beside the platform
/// builds: `applied`, under the gem's own patch.
fn ruby_event(newly: bool) -> serde_json::Value {
    let mut details = serde_json::json!({ "gemFix": UUID, "mode": "hosted" });
    if newly {
        details["newlyPatched"] = serde_json::json!(true);
    }
    serde_json::json!({ "action": "applied", "purl": PURL, "uuid": UUID, "details": details })
}

/// The uncounted event of a build that stays upstream's gem.
fn upstream_event(platform: &str) -> serde_json::Value {
    serde_json::json!({
        "action": "skipped",
        "purl": platform_purl(platform),
        "errorCode": "gem_upstream_build_kept",
        "reason": format!(
            "the patch registry serves upstream's own gem for {platform}: no patched build yet"
        ),
        "details": { "gemFix": UUID, "platform": platform, "mode": "hosted" },
    })
}

/// `events`, by platform as [`hosted_events`] orders a run's.
fn by_platform(mut events: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    events.sort_by_key(|event| {
        let platform = event["details"]["platform"].as_str();
        platform.map(str::to_string)
    });
    events
}

/// A gem bundler locks as precompiled platform builds, with a patched build
/// for every platform the lock names, against the REAL bundler end to end:
///
///   1. upstream publishes the gem as a ruby gem AND as platform gems (this
///      machine's platform, and a foreign one); the real `bundle install` +
///      `bundle lock --add-platform` lock both platform builds and install
///      this machine's platform gem. `ruby_entry` picks the lock's
///      PLATFORMS: without `ruby` the lock holds the platform builds
///      alone, with it bundler keeps the ruby-platform
///      `name (version)` entry beside them (what bundler 4 locks by default
///      for a gem that also ships a ruby gem), and that entry moves too;
///   2. the hosted scan asks for the gem patch's reference alone, moves
///      EVERY entry into the `GEM` section of the registry snapshot that
///      reference names, pins `DEPENDENCIES`, and (on a `CHECKSUMS` lock)
///      sets each entry to the sha256 the registry serves for it — the lock
///      the real `bundle lock` writes for that Gemfile, byte for byte. It
///      reports one `applied` event per locked build, each under that
///      build's own patch, and replaces the platform copy bundler had
///      installed with the patched platform gem;
///   3. a fresh checkout's FROZEN `bundle install` fetches exactly this
///      machine's patched build from the patch registry (never the ruby
///      gem, so nothing is compiled), leaves the lock byte-identical, and
///      Ruby loads the PATCHED file from the platform build;
///   4. a re-scan is a no-op, and offers no patch as newer although a
///      search returns the platform gems' own patches beside the gem's;
///   5. `rollback` hands back the pre-scan pair byte for byte and puts the
///      installed copy back on the upstream platform gem;
///   6. standalone `vex` attests the gem from the lock, hash-verified
///      against the installed platform build.
///
/// With `takeover`, a vendored run takes the gem over before step 5, each
/// platform's tree from that platform's own patch (asked for in one
/// request), which leaves the patched platform copy the hosted scan
/// installed. Step 5 is then a vendored unwind, and `remove` and
/// `vendor --revert` run over copies of the project as well: each must put
/// the installed platform copy back on the upstream platform gem.
async fn platform_prebuilds_install_frozen_and_roll_back(
    tag: &str,
    checksums_lock: bool,
    ruby_entry: bool,
    takeover: bool,
) {
    // Bundler locks the specific platform's gem from 2.2; `CHECKSUMS` from
    // 2.6. Vendor takes platform gems from a lock bundler 2.3 or newer wrote.
    let floor = match (checksums_lock, takeover) {
        (true, _) => (2, 6),
        (false, true) => (2, 3),
        (false, false) => (2, 2),
    };
    let Some(mut p) = PlatformProject::start(tag, floor, checksums_lock, ruby_entry, &[]).await
    else {
        return;
    };
    let (own, foreign) = (p.own.clone(), p.foreign.clone());
    let every = [
        (own.as_str(), Has::Patched),
        (foreign.as_str(), Has::Patched),
    ];
    let index_url = p.serve(Some(&every)).await;
    let registry = index_url[p.api().len()..].to_string();
    let warm_lib = p.installed_lib(&p.fx.proj);
    let (orig, patched) = (p.service.orig.clone(), p.service.patched.clone());

    // 2. The hosted scan.
    let vex = ["--vex", "out.vex.json", "--vex-product", PRODUCT];
    let scanned = p.mark().await;
    let env = p.scan(&vex);
    assert_eq!(env["status"], "success", "envelope: {env}");
    let reported = |newly: bool| {
        let mut events = vec![patched_event(&own, newly), patched_event(&foreign, newly)];
        if ruby_entry {
            events.push(ruby_event(newly));
        }
        by_platform(events)
    };
    assert_eq!(
        hosted_events(&env),
        reported(true),
        "one `applied` event per locked build, each under its own patch: {env}"
    );
    assert_eq!(
        env["summary"]["applied"],
        reported(true).len(),
        "every patched build is counted: {env}"
    );
    // Nothing warns about platforms, and the platform copy bundler had
    // installed is the patched build now.
    let codes = warning_codes(&env);
    let said = |code: &str| codes.iter().any(|said| said == code);
    for code in [
        "redirect_gem_platform_unsupported",
        "redirect_gem_stale_install",
        "redirect_gem_frozen_install",
    ] {
        assert!(!said(code), "no {code}: {env}");
    }
    assert_eq!(
        said("redirect_gem_no_checksums_section"),
        !checksums_lock,
        "{env}"
    );
    assert!(
        said("redirect_gem_install_refreshed"),
        "the warm platform install is refreshed: {env}"
    );
    assert_eq!(
        std::fs::read_to_string(&warm_lib).unwrap(),
        patched,
        "the installed platform copy holds the patched file"
    );
    assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
    let asked = p.references_since(scanned).await;
    assert!(
        !asked.is_empty() && asked.iter().all(|uuids| uuids == &[UUID]),
        "the scan asks for the reference of the gem's own patch alone: {asked:?}"
    );

    let lock = p.assert_hosted_pair(&index_url, &[(&own, true), (&foreign, true)]);
    let gemfile = p.gemfile();
    // The lock is the one the host bundler writes for that Gemfile over the
    // pre-scan lock, byte for byte.
    assert_eq!(
        lock,
        p.bundler_lock("relock", &gemfile, &p.pristine_lock()),
        "the scan's lock must be what bundler {} writes for the redirected Gemfile",
        p.fx.bundler.version
    );
    assert_no_redirect_ledger(&p.fx.proj);

    // 3. A fresh checkout's frozen install: exactly this machine's patched
    //    build, from the patch registry.
    let installing = p.mark().await;
    let fresh = p.install_fresh("fresh", &[("BUNDLE_FROZEN", "true")]);
    p.assert_installed(&fresh, true);
    let (fetched, redirected) = p.fetched_since(installing).await;
    assert_eq!(
        fetched,
        [format!("{registry}gems/{}.gem", p.own_leaf())],
        "the frozen install fetches the one platform gem of this machine"
    );
    assert_eq!(redirected, Vec::<String>::new(), "and nothing of upstream");

    // 4. A re-scan changes nothing.
    let env = p.scan(&vex);
    assert_eq!(p.lock(), lock, "a re-scan leaves the lock byte-identical");
    assert_eq!(p.gemfile(), gemfile);
    assert_eq!(hosted_events(&env), reported(false), "{env}");
    let codes = warning_codes(&env);
    for code in [
        "redirect_gem_install_refreshed",
        "redirect_gem_stale_install",
        "redirect_gem_platform_unsupported",
    ] {
        assert!(
            !codes.iter().any(|said| said == code),
            "a re-scan has nothing to refresh, warn about or skip: {env}"
        );
    }
    assert_eq!(
        env["updates"],
        serde_json::json!([]),
        "a platform gem's own patch is no newer patch of the gem: {env}"
    );

    // 5. Rollback: the pre-scan pair, byte for byte, and the installed
    //    copy back on the upstream platform gem.
    p.commit_pair();
    if takeover {
        let taking = p.mark().await;
        let (code, stdout, stderr) =
            p.unwind(&p.fx.proj, &["get", UUID, "--mode", "vendored", "--yes"]);
        assert_eq!(code, 0, "takeover:\nstdout:\n{stdout}\nstderr:\n{stderr}");
        let vendored_lock = p.lock();
        assert!(
            vendored_lock.starts_with("PATH\n  remote: .socket/vendor/gem/"),
            "premise: the gem is vendored:\n{vendored_lock}\nstdout:\n{stdout}"
        );
        assert_eq!(
            std::fs::read_to_string(&warm_lib).unwrap(),
            patched,
            "premise: the takeover leaves the patched platform copy installed"
        );
        // Each platform's tree comes from that platform's own patch: the
        // gem patch's reference, then ONE request for both.
        let mut own_patches = [build_uuid(&own), build_uuid(&foreign)];
        own_patches.sort();
        let asked: Vec<Vec<String>> = p
            .references_since(taking)
            .await
            .into_iter()
            .filter(|uuids| uuids != &[UUID])
            .map(|mut uuids| {
                uuids.sort();
                uuids
            })
            .collect();
        assert_eq!(
            asked,
            [own_patches.to_vec()],
            "the platform patches are asked for in one request"
        );
        // `remove` and `vendor --revert`, each over its own copy of the
        // project; `rollback` runs on the project itself below.
        for command in ["remove", "vendor --revert"] {
            let dir = p.fx.tmp.path().join(format!("unwind-{}", &command[..6]));
            copy_dir_recursive(&p.fx.proj, &dir);
            // What a `bundle cache` taken under the hosted pin left: this
            // machine's patched build in Bundler's cache dir.
            let cached = dir
                .join("vendor/cache")
                .join(format!("{}.gem", p.own_leaf()));
            std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
            std::fs::write(&cached, &p.service.builds[&build_token(Some(&own))]).unwrap();
            let argv: &[&str] = match command {
                "remove" => &["remove", PURL, "--yes"],
                _ => &["vendor", "--revert", "--yes"],
            };
            let (code, stdout, stderr) = p.unwind(&dir, argv);
            assert_eq!(code, 0, "{command}:\nstdout:\n{stdout}\nstderr:\n{stderr}");
            assert_eq!(
                std::fs::read_to_string(dir.join("Gemfile.lock")).unwrap(),
                p.as_committed(&p.pristine_lock()),
                "{command} must hand the lock back byte for byte"
            );
            assert_eq!(
                std::fs::read_to_string(p.installed_lib(&dir)).unwrap(),
                orig,
                "{command}: the installed platform copy is the upstream build again:\n{stdout}"
            );
            assert!(
                stdout.contains("upstream_gem_install_refreshed")
                    && !stdout.contains("upstream_gem_stale_install"),
                "{command}: the copy is refreshed, and nothing is left patched:\n{stdout}"
            );
            // Both commands report a vendored unwind's advisories as events.
            let env: serde_json::Value = serde_json::from_str(&stdout)
                .unwrap_or_else(|e| panic!("{command}: not JSON: {e}\nstdout:\n{stdout}"));
            let named: Vec<String> = env["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["errorCode"] == "upstream_gem_stale_cache")
                .map(|e| e.to_string())
                .collect();
            assert_eq!(named.len(), 1, "{command}: one stale-cache warning: {env}");
            assert!(
                named[0].contains(&cached.display().to_string())
                    && named[0].contains("non-upstream"),
                "{command}: the patched platform archive in the cache dir is named: {}",
                named[0]
            );
        }
    }
    let stdout = p.roll_back();
    assert_eq!(
        std::fs::read_to_string(&warm_lib).unwrap(),
        orig,
        "the installed platform copy is the upstream build again"
    );
    assert!(
        !stdout.contains("upstream_gem_stale_install")
            && !stdout.contains("upstream_gem_stale_cache"),
        "nothing is left on the patched build:\n{stdout}"
    );
    // The case whose pair still names the mock upstream: bundler loads the
    // upstream code, and a reinstall from the gem home's archive succeeds.
    if takeover && !checksums_lock {
        let probe = "require \"vuln_gem\"; print VulnGem.status";
        for args in [&["install"][..], &["pristine"]] {
            bundle_ok(&p.fx.proj, args);
            let run = bundle(&p.fx.proj, &["exec", "ruby", "-e", probe]);
            assert_eq!(
                String::from_utf8_lossy(&run.stdout),
                "VULNERABLE",
                "bundle {args:?} leaves the upstream code loaded:\n{}",
                String::from_utf8_lossy(&run.stderr)
            );
        }
    }

    // 6. Standalone VEX over the fresh checkout bundler installed.
    manifestless_vex_matrix(&p.fx, &fresh).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_platform_prebuilds_install_frozen_and_roll_back() {
    platform_prebuilds_install_frozen_and_roll_back(
        "platform-prebuilds-checksums",
        true,
        false,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_platform_prebuilds_beside_the_ruby_entry_install_frozen_and_roll_back() {
    platform_prebuilds_install_frozen_and_roll_back(
        "platform-prebuilds-ruby-entry",
        true,
        true,
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.2); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_platform_prebuilds_without_checksums_install_frozen_and_roll_back() {
    platform_prebuilds_install_frozen_and_roll_back("platform-prebuilds", false, false, false)
        .await;
}

/// A platform gem that went from hosted to vendored, then unwound.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_vendored_unwind_restores_a_platform_install_the_hosted_scan_patched() {
    platform_prebuilds_install_frozen_and_roll_back(
        "platform-prebuilds-takeover-checksums",
        true,
        false,
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.3); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_vendored_unwind_restores_a_platform_install_without_checksums() {
    platform_prebuilds_install_frozen_and_roll_back(
        "platform-prebuilds-takeover",
        false,
        false,
        true,
    )
    .await;
}

/// A lock with ONE patched platform and one the registry still serves as
/// upstream's own gem, on a `CHECKSUMS` lock, against the REAL bundler.
/// `own_patched` says which of the two this machine is, so the two cases
/// are a machine of the patched platform and a machine of the other:
///
///   1. the scan moves BOTH builds to the patch registry (one reference
///      request, for the gem's patch, asking for the list), pins the
///      patched build's sha256 and keeps upstream's for the other, and
///      reports the patched build under its own patch and the other as
///      kept, with no warning. The lock is what the real `bundle lock`
///      writes for that Gemfile, and a later `bundle lock` leaves it alone;
///   2. `bundle install` of a fresh checkout works frozen, in deployment
///      mode and unfrozen, and leaves the lock byte-identical: a machine of
///      the patched platform gets the PATCHED gem from the registry, a
///      machine of the other gets UPSTREAM's gem, which the registry
///      answers with a 302 that bundler follows to the upstream file host;
///   3. the scan itself downloads the patched build to refresh the copy
///      bundler had installed on the patched platform, and nothing at all
///      on the other, whose installed copy is upstream's gem as its lock
///      entry pins it;
///   4. a re-scan changes nothing, reports no build as newly patched and
///      offers no newer patch; a person reads one plain line;
///   5. `rollback` hands back the pre-scan pair byte for byte.
async fn one_platform_patched_and_one_on_upstream(tag: &str, own_patched: bool) {
    let Some(mut p) = PlatformProject::start(tag, (2, 6), true, false, &[]).await else {
        return;
    };
    let (own, foreign) = (p.own.clone(), p.foreign.clone());
    let (patched, upstream) = if own_patched {
        (own.as_str(), foreign.as_str())
    } else {
        (foreign.as_str(), own.as_str())
    };
    let index_url = p
        .serve(Some(&[(patched, Has::Patched), (upstream, Has::Upstream)]))
        .await;
    let own_file = format!("{}gems/{}.gem", &index_url[p.api().len()..], p.own_leaf());
    let warm_lib = p.installed_lib(&p.fx.proj);
    let installed = if own_patched {
        p.service.patched.clone()
    } else {
        p.service.orig.clone()
    };

    // 1. The scan.
    let scanned = p.mark().await;
    let env = p.scan(&[]);
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(
        hosted_events(&env),
        by_platform(vec![patched_event(patched, true), upstream_event(upstream)]),
        "{env}"
    );
    let summary = &env["summary"];
    assert_eq!(
        (&summary["applied"], &summary["skipped"], &summary["failed"]),
        (
            &serde_json::json!(1),
            &serde_json::json!(0),
            &serde_json::json!(0)
        ),
        "the build on upstream's gem is counted nowhere: {env}"
    );
    let refreshed: &[&str] = if own_patched {
        &["redirect_gem_install_refreshed"]
    } else {
        &[]
    };
    assert_eq!(warning_codes(&env), refreshed, "{env}");
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        serde_json::json!(["Gemfile", "Gemfile.lock"])
    );
    let lock = p.assert_hosted_pair(&index_url, &[(patched, true), (upstream, false)]);
    assert_eq!(
        lock,
        p.bundler_lock("relock", &p.gemfile(), &p.pristine_lock()),
        "the scan's lock must be what bundler {} writes for the redirected Gemfile",
        p.fx.bundler.version
    );
    assert_eq!(
        p.references_since(scanned).await,
        [[UUID]],
        "one reference request, for the gem's own patch"
    );
    assert_eq!(
        p.views_since(scanned).await,
        Vec::<String>::new(),
        "no patch record is fetched"
    );
    // 3. What the scan itself downloaded.
    let (fetched, redirected) = p.fetched_since(scanned).await;
    let refresh: &[String] = if own_patched {
        std::slice::from_ref(&own_file)
    } else {
        &[]
    };
    assert_eq!(
        fetched, refresh,
        "the scan downloads the patched build of this machine's platform, when there is one"
    );
    assert_eq!(redirected, Vec::<String>::new());
    assert_eq!(std::fs::read_to_string(&warm_lib).unwrap(), installed);

    // A later `bundle lock` has nothing to change.
    bundle_ok(&p.fx.proj, &["lock"]);
    assert_eq!(
        p.lock(),
        lock,
        "`bundle lock` leaves the lock byte-identical"
    );

    // 2. A machine of this platform installs from a fresh checkout.
    let modes: [(&str, &[(&str, &str)]); 3] = [
        ("frozen", &[("BUNDLE_FROZEN", "true")]),
        ("deployment", &[("BUNDLE_DEPLOYMENT", "true")]),
        ("unfrozen", &[]),
    ];
    for (name, envs) in modes {
        let installing = p.mark().await;
        let fresh = p.install_fresh(name, envs);
        p.assert_installed(&fresh, own_patched);
        let (fetched, redirected) = p.fetched_since(installing).await;
        assert_eq!(
            fetched,
            std::slice::from_ref(&own_file),
            "{name}: bundler asks the patch registry for this machine's platform gem alone"
        );
        let handed_on: &[String] = if own_patched {
            &[]
        } else {
            &[format!("{}.gem", p.own_leaf())]
        };
        assert_eq!(
            redirected, handed_on,
            "{name}: the registry hands a platform with no patched build on to the upstream \
             file host, and serves a patched build itself"
        );
    }

    // 4. A re-scan.
    let rescanned = p.mark().await;
    let env = p.scan(&[]);
    assert_eq!(p.lock(), lock, "a re-scan leaves the lock byte-identical");
    assert_eq!(
        hosted_events(&env),
        by_platform(vec![
            patched_event(patched, false),
            upstream_event(upstream)
        ]),
        "in place, not newly patched: {env}"
    );
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(env["redirect"]["rewrittenFiles"], serde_json::json!([]));
    assert_eq!(env["updates"], serde_json::json!([]), "{env}");
    assert_eq!(p.references_since(rescanned).await, [[UUID]]);
    let (code, stdout, stderr) = p.hosted(&p.fx.proj, &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 package is already on hosted patches; nothing to rewrite.\n"),
        "one package, whatever its builds:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: patched for {patched}; upstream gem kept for {upstream} (no \
             patched build yet)\n"
        )),
        "{stdout}"
    );
    assert!(!stderr.contains("Warning"), "{stderr}");

    // 5. Rollback.
    let stdout = p.roll_back();
    assert_eq!(
        std::fs::read_to_string(&warm_lib).unwrap(),
        p.service.orig,
        "the installed platform copy is upstream's gem"
    );
    assert_eq!(
        stdout.contains("upstream_gem_install_refreshed"),
        own_patched,
        "only a patched copy is put back:\n{stdout}"
    );
    assert!(
        !stdout.contains("upstream_gem_stale_install")
            && !stdout.contains("upstream_gem_stale_cache"),
        "nothing is left on the patched build:\n{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_machine_of_the_patched_platform_installs_the_patched_gem() {
    one_platform_patched_and_one_on_upstream("platform-one-patched-own", true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_machine_of_a_platform_with_no_patched_build_installs_upstreams_gem() {
    one_platform_patched_and_one_on_upstream("platform-one-patched-other", false).await;
}

/// A gem is moved only once a locked build is patched and every locked
/// platform is listed, and until then a run says so quietly. On the lock
/// the real bundler wrote (with `CHECKSUMS`):
///
///   1. no locked build has a patched build: exit 0, both files
///      byte-identical, no warning, one skipped event, one plain line;
///   2. this machine's platform has one, and the other is missing from the
///      list (its patched build is still being made): the same, under its
///      own code and line;
///   3. the list has it: the run moves the gem, and a fresh checkout
///      installs the patched gem frozen.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_platform_gem_waits_quietly_for_its_patched_builds() {
    let Some(mut p) = PlatformProject::start("platform-waits", (2, 6), true, false, &[]).await
    else {
        return;
    };
    let (own, foreign) = (p.own.clone(), p.foreign.clone());
    let mut locked = [own.as_str(), foreign.as_str()];
    locked.sort();

    // 1. No locked build is patched.
    let none = [
        (own.as_str(), Has::Upstream),
        (foreign.as_str(), Has::Upstream),
    ];
    p.serve(Some(&none)).await;
    p.assert_left_alone(
        "redirect_gem_no_patched_build",
        &format!(
            "{DEP} {DEP_VERSION}: no patched build yet for {}, {}; left on its upstream registry",
            locked[0], locked[1]
        ),
    );

    // 2. A locked platform is missing from the list.
    let building = [
        (own.as_str(), Has::Patched),
        (foreign.as_str(), Has::Building),
    ];
    p.serve(Some(&building)).await;
    p.assert_left_alone(
        "redirect_gem_build_pending",
        &format!(
            "{DEP} {DEP_VERSION}: the patch registry does not list {foreign} yet (a patched build \
             is still being made); left as it is until it does"
        ),
    );

    // 3. The build is there.
    let every = [
        (own.as_str(), Has::Patched),
        (foreign.as_str(), Has::Patched),
    ];
    let index_url = p.serve(Some(&every)).await;
    let env = p.scan(&[]);
    assert_eq!(
        hosted_events(&env),
        by_platform(vec![
            patched_event(&own, true),
            patched_event(&foreign, true)
        ]),
        "{env}"
    );
    assert_eq!(
        warning_codes(&env),
        ["redirect_gem_install_refreshed"],
        "{env}"
    );
    p.assert_hosted_pair(&index_url, &[(&own, true), (&foreign, true)]);
    let fresh = p.install_fresh("fresh", &[("BUNDLE_FROZEN", "true")]);
    p.assert_installed(&fresh, true);
}

/// A newer registry snapshot upgrades a hosted lock. This machine's
/// platform has no patched build at first, so the lock pins upstream's
/// gem for it and bundler installs that. Once the build is published the
/// reference names a newer snapshot:
///
///   1. the next scan rewrites the registry URL in the Gemfile and the
///      lock and the ONE checksum that changed, reports that build as
///      newly patched and the other as in place, and replaces the copy
///      bundler had installed with the patched gem, downloaded from the
///      newer snapshot;
///   2. `bundle lock` leaves that lock alone, and `bundle install` (frozen,
///      from a fresh checkout, and in the project) installs the newly
///      patched gem;
///   3. the earlier snapshot answers as it did: a checkout of the earlier
///      pair still installs upstream's gem frozen;
///   4. `rollback` hands back the pre-scan pair byte for byte.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_newer_registry_snapshot_installs_the_newly_patched_build() {
    let Some(mut p) =
        PlatformProject::start("platform-newer-snapshot", (2, 6), true, false, &[]).await
    else {
        return;
    };
    let (own, foreign) = (p.own.clone(), p.foreign.clone());
    let warm_lib = p.installed_lib(&p.fx.proj);
    let at_first = [
        (own.as_str(), Has::Upstream),
        (foreign.as_str(), Has::Patched),
    ];
    let first = p.serve(Some(&at_first)).await;
    let env = p.scan(&[]);
    assert_eq!(
        hosted_events(&env),
        by_platform(vec![upstream_event(&own), patched_event(&foreign, true)]),
        "{env}"
    );
    let first_lock = p.assert_hosted_pair(&first, &[(&own, false), (&foreign, true)]);
    let first_gemfile = p.gemfile();
    let earlier = p.install_fresh("earlier", &[("BUNDLE_FROZEN", "true")]);
    p.assert_installed(&earlier, false);
    // The earlier pair, with nothing installed: for a person's run below.
    let committed = stage_fresh_checkout(&p.fx, "committed");

    // The patched build of this machine's platform is published.
    let every = [
        (own.as_str(), Has::Patched),
        (foreign.as_str(), Has::Patched),
    ];
    let second = p.serve(Some(&every)).await;
    assert_ne!(first, second, "a newer snapshot is another URL");

    // 1. The upgrade.
    let upgrading = p.mark().await;
    let env = p.scan(&[]);
    assert_eq!(
        hosted_events(&env),
        by_platform(vec![
            patched_event(&own, true),
            patched_event(&foreign, false)
        ]),
        "{env}"
    );
    assert_eq!(
        warning_codes(&env),
        ["redirect_gem_install_refreshed"],
        "{env}"
    );
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        serde_json::json!(["Gemfile", "Gemfile.lock"])
    );
    let lock = p.assert_hosted_pair(&second, &[(&own, true), (&foreign, true)]);
    let pin = |patched: bool| {
        let token = build_token(Some(&own));
        let sha = p.service.sha(Some(&own), patched);
        format!("  {DEP} ({token}) sha256={sha}\n")
    };
    assert_eq!(
        lock,
        first_lock
            .replace(&first, &second)
            .replace(&pin(false), &pin(true)),
        "the URL and the one checksum that changed"
    );
    assert_eq!(p.gemfile(), first_gemfile.replace(&first, &second));
    let (fetched, redirected) = p.fetched_since(upgrading).await;
    assert_eq!(
        fetched,
        [format!(
            "{}gems/{}.gem",
            &second[p.api().len()..],
            p.own_leaf()
        )],
        "the refresh takes the patched build from the newer snapshot"
    );
    assert_eq!(redirected, Vec::<String>::new());
    assert_eq!(
        std::fs::read_to_string(&warm_lib).unwrap(),
        p.service.patched,
        "the copy bundler had installed is the patched build"
    );
    // For a person: which build this run found patched.
    let (code, stdout, stderr) = p.hosted(&committed, &["scan"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "\n{DEP} {DEP_VERSION}: now also patched for {own}; already patched for {foreign}\n"
        )),
        "{stdout}"
    );
    assert!(!stderr.contains("Warning"), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(committed.join("Gemfile.lock")).unwrap(),
        lock
    );

    // 2. Bundler agrees with the lock and installs the patched gem.
    bundle_ok(&p.fx.proj, &["lock"]);
    assert_eq!(
        p.lock(),
        lock,
        "`bundle lock` leaves the lock byte-identical"
    );
    let fresh = p.install_fresh("fresh", &[("BUNDLE_FROZEN", "true")]);
    p.assert_installed(&fresh, true);
    bundle_ok(&p.fx.proj, &["install"]);
    assert_eq!(p.lock(), lock);
    p.assert_installed(&p.fx.proj, true);

    // 3. The earlier snapshot answers as it did.
    let again = p.fx.tmp.path().join("earlier-again");
    std::fs::create_dir_all(&again).unwrap();
    std::fs::write(again.join("Gemfile"), &first_gemfile).unwrap();
    std::fs::write(again.join("Gemfile.lock"), &first_lock).unwrap();
    copy_dir_recursive(&p.fx.proj.join(".bundle"), &again.join(".bundle"));
    let install = bundle_env(&again, &["install"], &[("BUNDLE_FROZEN", "true")]);
    assert!(
        install.status.success(),
        "the earlier pair still installs frozen:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    p.assert_installed(&again, false);

    // 4. Rollback.
    let stdout = p.roll_back();
    assert_eq!(
        std::fs::read_to_string(&warm_lib).unwrap(),
        p.service.orig,
        "the installed platform copy is the upstream build again"
    );
    assert!(
        !stdout.contains("upstream_gem_stale_install")
            && !stdout.contains("upstream_gem_stale_cache"),
        "nothing is left on the patched build:\n{stdout}"
    );
}

/// `bundle lock --add-platform` on a hosted lock: the real bundler resolves
/// the new platform's gem from the patch registry, whose snapshot lists
/// every platform gem of the version, and pins the sha256 listed there: the
/// patched build's for a platform that has one, upstream's for one that
/// has none. Nothing else of the lock changes, and the Gemfile not at all.
/// The next scan reports the new builds with the others and writes nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_bundle_lock_add_platform_resolves_from_the_patch_registry() {
    // Two platforms the lock does not name at first, neither this
    // machine's nor the foreign one.
    const WITH_BUILD: &str = "aarch64-linux";
    const WITHOUT_BUILD: &str = "x64-mingw-ucrt";
    let more = [WITH_BUILD, WITHOUT_BUILD];
    let Some(mut p) = PlatformProject::start("platform-add", (2, 6), true, false, &more).await
    else {
        return;
    };
    let (own, foreign) = (p.own.clone(), p.foreign.clone());
    let listing = [
        (own.as_str(), Has::Patched),
        (foreign.as_str(), Has::Upstream),
        (WITH_BUILD, Has::Patched),
        (WITHOUT_BUILD, Has::Upstream),
    ];
    let index_url = p.serve(Some(&listing)).await;
    let env = p.scan(&[]);
    assert_eq!(
        hosted_events(&env),
        by_platform(vec![patched_event(&own, true), upstream_event(&foreign)]),
        "the builds the lock names: {env}"
    );
    let hosted_lock = p.assert_hosted_pair(&index_url, &[(&own, true), (&foreign, false)]);
    let gemfile = p.gemfile();

    for platform in more {
        bundle_ok(&p.fx.proj, &["lock", "--add-platform", platform]);
    }
    let lock = p.lock();
    assert_eq!(p.gemfile(), gemfile, "bundler leaves the Gemfile alone");
    // The lock gained exactly the new platforms, their entries and their
    // checksums, and lost nothing.
    let had: Vec<&str> = hosted_lock.lines().collect();
    let mut gained: Vec<&str> = lock.lines().filter(|line| !had.contains(line)).collect();
    gained.sort();
    let pin = |platform: &str, patched: bool| {
        let token = build_token(Some(platform));
        let sha = p.service.sha(Some(platform), patched);
        format!("  {DEP} ({token}) sha256={sha}")
    };
    let mut want = vec![
        format!("  {WITH_BUILD}"),
        format!("  {WITHOUT_BUILD}"),
        format!("    {DEP} ({})", build_token(Some(WITH_BUILD))),
        format!("    {DEP} ({})", build_token(Some(WITHOUT_BUILD))),
        pin(WITH_BUILD, true),
        pin(WITHOUT_BUILD, false),
    ];
    want.sort();
    assert_eq!(
        gained, want,
        "the new platforms resolve from the patch registry:\n{lock}"
    );
    let lines: Vec<&str> = lock.lines().collect();
    let lost: Vec<&&str> = had.iter().filter(|line| !lines.contains(line)).collect();
    assert_eq!(lost, Vec::<&&str>::new(), "nothing else changes:\n{lock}");
    let registry_section = lock
        .split("\n\n")
        .find(|section| section.contains(&format!("remote: {index_url}\n")))
        .unwrap_or_else(|| panic!("no GEM section of {index_url}:\n{lock}"));
    for platform in more {
        assert!(
            registry_section.contains(&format!(
                "    {DEP} ({})\n      {TRANSITIVE}",
                build_token(Some(platform))
            )),
            "the {platform} build is under the patch registry:\n{lock}"
        );
    }

    // The next scan reports the new builds and writes nothing.
    let env = p.scan(&[]);
    assert_eq!(p.lock(), lock, "the scan changes nothing:\n{env}");
    assert_eq!(p.gemfile(), gemfile);
    assert_eq!(env["redirect"]["rewrittenFiles"], serde_json::json!([]));
    assert_eq!(warning_codes(&env), Vec::<String>::new(), "{env}");
    assert_eq!(
        hosted_events(&env),
        by_platform(vec![
            patched_event(&own, false),
            upstream_event(&foreign),
            patched_event(WITH_BUILD, false),
            upstream_event(WITHOUT_BUILD),
        ]),
        "{env}"
    );
    let fresh = p.install_fresh("fresh", &[("BUNDLE_FROZEN", "true")]);
    p.assert_installed(&fresh, true);
}

/// The stale-install refresh downloads `gems/<file>` from the patch
/// registry, which may answer a file with a redirect (it does for every
/// platform it has no patched build of). The download follows it: here
/// the registry answers the file of this machine's patched build with a
/// 302 to another host, and the copy bundler had installed is replaced
/// with the gem that host serves, verified against the sha256 the list
/// names.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real ruby/gem/bundler (>= 2.6 for the CHECKSUMS lock); \
            the unpinned `test` job skips it, an e2e job with a pinned toolchain runs it via --ignored"]
async fn gem_hosted_refresh_follows_a_redirect_from_the_patch_registry() {
    let Some(mut p) =
        PlatformProject::start("platform-refresh-302", (2, 6), true, false, &[]).await
    else {
        return;
    };
    let (own, foreign) = (p.own.clone(), p.foreign.clone());
    let every = [
        (own.as_str(), Has::Patched),
        (foreign.as_str(), Has::Patched),
    ];
    let index_url = p.serve(Some(&every)).await;
    let file = format!("{}.gem", p.own_leaf());
    let elsewhere = format!("/elsewhere/{file}");
    Mock::given(method("GET"))
        .and(path(format!("{}gems/{file}", &index_url[p.api().len()..])))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}{elsewhere}", p.files.uri()).as_str())
                .insert_header("Cache-Control", "no-store"),
        )
        .with_priority(1)
        .mount(&p.fx._server)
        .await;
    Mock::given(method("GET"))
        .and(path(elsewhere.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            p.service.builds[&build_token(Some(&own))].clone(),
            "application/octet-stream",
        ))
        .mount(&p.files)
        .await;

    let env = p.scan(&[]);
    assert_eq!(
        warning_codes(&env),
        ["redirect_gem_install_refreshed"],
        "{env}"
    );
    assert_eq!(
        std::fs::read_to_string(p.installed_lib(&p.fx.proj)).unwrap(),
        p.service.patched,
        "the installed copy is the patched build"
    );
    let served = p.files.received_requests().await.unwrap_or_default();
    let served: Vec<&str> = served.iter().map(|request| request.url.path()).collect();
    assert_eq!(served, [elsewhere], "the download followed the redirect");
}
