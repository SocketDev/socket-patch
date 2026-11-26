//! Real-bundler capstone e2e for `socket-patch vendor` — the gem
//! committability proof on the HOST toolchain (the docker twin is
//! `docker_e2e_vendor_gem.rs`; this suite adds coverage on developer/CI
//! hosts that carry a modern bundler).
//!
//! Drives the REAL bundler (network used for fixture setup only):
//!   1. `bundle install` a Gemfile pinning `rack "~> 3.1"` into a
//!      project-local `vendor/bundle` (private `.bundle/config`, ambient
//!      `BUNDLE_*` scrubbed).
//!   2. Hand-stage a `.socket/` manifest + blob whose before/after Git-blob
//!      hashes are computed from the ACTUAL installed bytes (the marker
//!      reopens `module Rack` with a probe constant so the patch is
//!      observable at `require` time).
//!   3. `socket-patch vendor --json --offline` — assert the vendored gem dir
//!      (patched bytes + materialized stub `rack.gemspec`) and the MANDATORY
//!      pair edit: the Gemfile line gains the exact pin + `path:`, the lock
//!      gains the canonical PATH section (before GEM) and the
//!      `rack (= <ver>)!` DEPENDENCIES pin.
//!   4. **VEX (vendored) leg**: `socket-patch vex` attests the patch against
//!      the committed gem dir with the `(vendored)` impact marker.
//!   5. **Fresh-checkout proof**: ONLY the committable files (Gemfile,
//!      Gemfile.lock, `.socket/`, `.bundle/`) travel to a new dir;
//!      `BUNDLE_FROZEN=true bundle install` exits 0 with a byte-stable lock,
//!      and `bundle exec ruby -e 'require "rack"'` resolves the probe
//!      constant FROM the vendored path.
//!   6. Idempotency: a re-vendor leaves both files byte-identical.
//!   7. **Revert proof**: `vendor --revert` byte-restores BOTH halves of the
//!      pair edit and removes `.socket/vendor/` entirely.
//!
//! The `get <uuid> --mode vendored` twin (v3.6) drives the same
//! fresh-checkout committability proof through get's per-advisory selector:
//! the patch record comes from a wiremock `view/{uuid}` (real hashes of the
//! ACTUAL installed bytes + inline `blobContent`), `--vendor-source build`
//! keeps the artifact build local, and the result must match a plain
//! `vendor` run by construction — `.socket/vendor/` artifact + ledger (a
//! detached entry) + the mandatory Gemfile/lock pair edit, with NO manifest
//! and NO `.socket/blobs`
//! (get's vendored download phase holds content in memory).
//!
//! MANIFEST-LESS VEX (every capstone, `vendored_manifestless_vex_matrix`,
//! on the fresh checkout after its frozen install): manifest deleted →
//! `vex --offline` attests `(vendored)` from the lock's PATH wiring + the
//! vendor ledger; both ledgers deleted → still attested from the lock +
//! the patch API (and by the embedded `apply --vex` / `vendor --vex`,
//! which touch nothing); `--offline` without ledgers → `record_unavailable`
//! with zero requests; lock-only revert (Gemfile keeps `path:`) →
//! `vendor_unwired` until the real bundler re-wires the PATH section on the
//! next unfrozen install (a frozen one refuses the pair), after which it is
//! attested again; full registry revert (ledgers + artifact kept) →
//! `vendor_unwired`, also under `--no-verify`.
//!
//! PLATFORM GEMS (`gem_vendor_platform_gems_fresh_checkout_bundle_install_and_revert`,
//! bundler >= 2.3): a gem the real bundler locks as precompiled platform
//! gems, from a local source that publishes it that way, is vendored as the
//! patched platform gem of every locked platform, each from that platform's
//! own patch, which the gem patch's reference names; the fresh checkout
//! loads the patched file from the tree of the platform it runs on, with no
//! request to the service. While a locked platform has no patched build
//! the gem is not vendored, and the run says so in one line.
//!
//! VERSION MATRIX: every capstone runs on bundler 1.17 → 4.x (verified
//! 1.17.3, 2.0.2 … 2.7.2, 4.0.15, 4.0.21 — the pair edit's PATH +
//! `(= v)!` shape installs frozen on all of them). Select with `PATH` and
//! name it in `SOCKET_PATCH_BUNDLER_E2E_VERSION`; `…_REQUIRED=1` turns a
//! missing toolchain into a failure (`common/bundler_e2e.rs`).
//!
//! Skips (with a println) when `bundle`/`ruby` are missing (unless
//! required) or when the fixture install cannot reach rubygems.org; every
//! assertion after that is hard.

#[path = "common/mod.rs"]
mod common;
use common::{binary, git_sha256, hermetic, hermetic_command, parse_json_envelope};

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/bundler_e2e.rs"]
mod bundler_e2e;
#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

/// Canonical lowercase patch uuid (a dedicated path level under
/// `.socket/vendor/gem/`) — also the probe constant's runtime value.
const UUID: &str = "3c4d5e6f-7a8b-4a1b-8c2d-0123456789ab";
const DEP: &str = "rack";
const GHSA: &str = "GHSA-vend-gem-host";
/// Org slug baked into the wiremock API paths of the get-driven twin.
const ORG: &str = "test-org";

// ── self-contained helpers ────────────────────────────────────────────

/// The real-bundler gate (`common/bundler_e2e.rs`: the version-matrix env
/// contract). Floor 1.17 — every bundler from the last 1.x on writes the
/// `PATH` + `(= v)!` shape the pair edit produces, and the version matrix
/// runs each major; `None` = skip (message printed).
fn gate(tag: &str) -> Option<bundler_e2e::Bundler> {
    bundler_e2e::gate("e2e_vendor_gem_build", tag, (1, 17), &|c| {
        cache_env::isolate(c);
    })
}

fn argv(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// Run the socket-patch binary in the hermetic environment
/// (`tests/common/hermetic.rs`: no ambient `SOCKET_*`, so a developer's
/// `SOCKET_DRY_RUN=1` etc. can't flip behavior) with the crawler's discovery
/// inputs scrubbed (`hermetic::scrub_crawler_inputs`: an ambient
/// `BUNDLE_PATH`, `BUNDLE_GEMFILE` or `~/.bundle/config` would point the
/// crawler away from the fixture).
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    hermetic::scrub_crawler_inputs(&mut cmd);
    cmd.current_dir(cwd);
    let _fixture = prebuilt_common::prepare_command(&mut cmd, cwd, args, &[]);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run `bundle <args>` in `cwd` with ambient `SOCKET_*` and bundler config
/// scrubbed ([`hermetic::Extra::Bundle`]: a developer's global bundler
/// config — a different BUNDLE_PATH, frozen mode, a RUBYOPT require — must
/// not leak into the fixture) and `BUNDLE_APP_CONFIG` pinned to the
/// project's own `.bundle/` so `bundle config set --local` writes a real
/// committable file. `GEM_HOME`/`GEM_PATH` stay: `bundle` resolves through
/// them under rvm/chruby, and every install here uses the project-local
/// `path` config, so no gem lands in the ambient gem home.
fn bundle(cwd: &Path, args: &[&str], frozen: bool) -> Output {
    let mut cmd = Command::new("bundle");
    cmd.args(args).current_dir(cwd);
    hermetic::scrub_socket_vars(&mut cmd);
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Bundle]);
    // After the scrub, which would otherwise take the sandbox's own
    // BUNDLE_USER_HOME straight back out.
    cache_env::isolate(&mut cmd);
    cmd.env("BUNDLE_APP_CONFIG", cwd.join(".bundle"));
    if frozen {
        cmd.env("BUNDLE_FROZEN", "true");
    }
    cmd.output().expect("failed to run bundle")
}

/// Base64 for the wiremock view's inline `blobContent`.
fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Write `.socket/manifest.json` + the after-hash blob (with a vulnerability
/// so the VEX leg has a statement to emit) so vendor runs fully offline.
fn stage_patch_with_vuln(proj: &Path, purl: &str, file_key: &str, before: &[u8], after: &[u8]) {
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": { purl: {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { file_key: {
                "beforeHash": git_sha256(before),
                "afterHash": git_sha256(after),
            }},
            "vulnerabilities": { GHSA: {
                "cves": ["CVE-2026-55555"],
                "summary": "gem capstone vex vuln",
                "severity": "high",
                "description": "d",
            }},
            "description": "capstone marker patch",
            "license": "MIT",
            "tier": "free",
        }}
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(after)), after).unwrap();
}

/// The plain resolved version of `name` from the lock's 4-space GEM spec line
/// (`    rack (3.1.16)`); platform-suffixed spec lines never match (their
/// parenthesized token does not start the version with a digit-only form we
/// accept here).
fn locked_gem_version(lock_text: &str, name: &str) -> Option<String> {
    let prefix = format!("    {name} (");
    for line in lock_text.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            let ver = rest.strip_suffix(')')?;
            if !ver.is_empty() && ver.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Some(ver.to_string());
            }
        }
    }
    None
}

// ── manifest-less VEX over the committed vendored state ────────────────

/// The vulnerability every capstone's patch record carries.
const VULNS: &[(&str, &[&str])] = &[(GHSA, &["CVE-2026-55555"])];
/// `--product` for the VEX legs (gem has no product auto-detect).
const PRODUCT: &str = "pkg:gem/app@1.0.0";

/// One committed vendored checkout the REAL bundler just installed from.
struct Vendored<'a> {
    bundler: &'a bundler_e2e::Bundler,
    /// The fresh checkout (Gemfile + lock + `.socket/` + `.bundle/`, then a
    /// frozen install).
    fresh: &'a Path,
    /// The project's committed `.bundle/` (bundler <= 2.0 persists
    /// `BUNDLE_FROZEN: "true"` into the checkout's config on a frozen
    /// install, so the fresh checkout's copy is no longer the committed one).
    committed_bundle: &'a Path,
    /// Scratch dir for copies.
    scratch: &'a Path,
    purl: &'a str,
    patched: &'a [u8],
    /// The pre-vendor (registry) manifest pair.
    pristine_gemfile: &'a [u8],
    pristine_lock: &'a [u8],
}

/// Manifest-less VEX over a vendored checkout, the GitHub-app shape:
///
///   1. `.socket/manifest.json` deleted: `vex --offline` attests
///      `(vendored)` from the lock's `PATH` wiring + the vendor ledger's
///      embedded record, hash-verified against the committed artifact;
///   2. both ledgers deleted too: still attested — discovery reads the lock,
///      the record comes from the patch API; the embedded `apply --vex` and
///      `vendor --vex` agree and touch nothing;
///   3. `--offline` with no ledgers: `record_unavailable`, ZERO requests;
///   4. lock-only revert (the Gemfile keeps `path:`): `vendor_unwired`,
///      because the lock an install is checked against resolves the gem
///      from the registry again — the REAL bundler re-resolves the gem from
///      the path on the next unfrozen install (a frozen one refuses the
///      pair), after which the ledger-less lock attests again;
///   4b. manifest-only revert (the lock keeps the `PATH` section, the
///      Gemfile lost its `path:`): `vendor_unwired` too, because bundler
///      takes the gem from the source the Gemfile names — the REAL bundler
///      refuses the pair frozen and, unfrozen, drops the section and
///      resolves the gem from the registry;
///   5. the manifest pair reverted to its registry version (ledgers +
///      artifact kept): `vendor_unwired`, online / offline, with and without
///      `--no-verify`.
fn vendored_manifestless_vex_matrix(v: &Vendored<'_>) {
    use vex_e2e_common::{
        assert_absent, assert_attested, assert_not_attested, patch_view, run_vex, strip_ledgers,
        strip_manifest, Marker, PatchApi, VexRun, VexVia,
    };
    let bin = binary();
    let fresh = v.fresh;
    let lock_name = "Gemfile.lock";
    let run = |base: VexRun| VexRun {
        product: Some(PRODUCT.into()),
        ..base
    };
    let api = PatchApi::start(vec![(
        UUID.into(),
        patch_view(
            UUID,
            v.purl,
            &[("lib/rack.rb", &git_sha256(v.patched))],
            VULNS,
        ),
    )]);
    let ledgers = fresh.join(".socket/vendor");
    let saved = v.scratch.join("saved-ledgers");
    std::fs::create_dir_all(&saved).unwrap();
    for f in ["state.json", "redirect-state.json"] {
        if ledgers.join(f).is_file() {
            std::fs::copy(ledgers.join(f), saved.join(f)).unwrap();
        }
    }
    let restore_ledgers = || {
        for entry in std::fs::read_dir(&saved).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), ledgers.join(entry.file_name())).unwrap();
        }
    };
    let lock = std::fs::read_to_string(fresh.join(lock_name)).unwrap();
    let ctx = format!("bundler {}\n--- {lock_name}\n{lock}", v.bundler.version);

    // 1. manifest-less, ledger kept, offline.
    strip_manifest(fresh);
    let out = run_vex(&bin, fresh, &run(VexRun::offline()));
    assert_eq!(out.code, Some(0), "manifest-less vex: {out}\n{ctx}");
    assert_attested(out.doc(), v.purl, UUID, Marker::Vendored, VULNS);
    assert_eq!(out.envelope["summary"]["verified"], 1, "{out}");
    api.assert_no_requests();

    // 2. no ledgers: lockfile discovery + the patch API.
    strip_ledgers(fresh);
    let out = run_vex(&bin, fresh, &run(VexRun::online(&api)));
    assert_eq!(out.code, Some(0), "ledger-less vex: {out}\n{ctx}");
    assert_attested(out.doc(), v.purl, UUID, Marker::Vendored, VULNS);
    assert!(api.view_requests(UUID) >= 1, "{:?}", api.requests());
    let gemfile_now = std::fs::read(fresh.join("Gemfile")).unwrap();
    for via in [VexVia::Apply, VexVia::Vendor] {
        let out = run_vex(&bin, fresh, &run(VexRun::online(&api).via(via)));
        assert_eq!(out.code, Some(0), "ledger-less {via:?} --vex: {out}\n{ctx}");
        assert_eq!(out.envelope["status"], "noManifest", "{via:?}: {out}");
        assert_eq!(out.envelope["vex"]["statements"], 1, "{via:?}: {out}");
        assert_attested(out.doc(), v.purl, UUID, Marker::Vendored, VULNS);
        assert_eq!(
            std::fs::read_to_string(fresh.join(lock_name)).unwrap(),
            lock,
            "{via:?}"
        );
        assert_eq!(
            std::fs::read(fresh.join("Gemfile")).unwrap(),
            gemfile_now,
            "{via:?}"
        );
        assert!(
            !fresh.join(".socket/manifest.json").exists(),
            "{via:?} wrote a manifest"
        );
    }

    // 3. offline, no ledgers.
    let before = api.request_count();
    let out = run_vex(&bin, fresh, &run(VexRun::offline()));
    assert_eq!(out.code, Some(1), "offline ledger-less vex: {out}");
    assert_not_attested(&out.envelope, v.purl, "record_unavailable");
    assert_eq!(api.request_count(), before, "--offline made requests");

    // 4. lock-only revert on a copy of the checkout.
    let copy = v.scratch.join("lock-only-revert");
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::copy(fresh.join("Gemfile"), copy.join("Gemfile")).unwrap();
    std::fs::write(copy.join(lock_name), v.pristine_lock).unwrap();
    common::fs_tree::copy_tree(&fresh.join(".socket"), &copy.join(".socket"));
    common::fs_tree::copy_tree(v.committed_bundle, &copy.join(".bundle"));
    for f in std::fs::read_dir(&saved).unwrap() {
        let f = f.unwrap();
        std::fs::copy(f.path(), copy.join(".socket/vendor").join(f.file_name())).unwrap();
    }
    let out = run_vex(&bin, &copy, &run(VexRun::offline()));
    assert_ne!(
        out.code,
        Some(0),
        "Gemfile `path:` kept, lock reverted, ledger kept: {out}\n{ctx}"
    );
    assert_absent(out.doc.as_ref(), v.purl);
    assert_not_attested(&out.envelope, v.purl, "vendor_unwired");
    let frozen = bundle(&copy, &["install"], true);
    assert!(
        !frozen.status.success(),
        "a frozen install must refuse the Gemfile/lock disagreement (bundler {})",
        v.bundler.version
    );
    // Bundler <= 2.0 persisted `BUNDLE_FROZEN: "true"` into the copy's
    // `.bundle/config` on that frozen attempt; a developer's unfrozen
    // install runs from the committed config.
    common::fs_tree::copy_tree(v.committed_bundle, &copy.join(".bundle"));
    let install = bundle(&copy, &["install"], false);
    assert!(
        install.status.success(),
        "unfrozen install over the mixed pair (bundler {}):\n{}",
        v.bundler.version,
        String::from_utf8_lossy(&install.stderr)
    );
    let relocked = std::fs::read_to_string(copy.join(lock_name)).unwrap();
    assert!(
        relocked.contains(&format!("PATH\n  remote: .socket/vendor/gem/{UUID}/")),
        "bundler must re-resolve the gem from the Gemfile's vendored path:\n{relocked}"
    );
    strip_ledgers(&copy);
    let out = run_vex(&bin, &copy, &run(VexRun::online(&api)));
    assert_eq!(
        out.code,
        Some(0),
        "re-wired, ledger-less: {out}\n{relocked}"
    );
    assert_attested(out.doc(), v.purl, UUID, Marker::Vendored, VULNS);

    // 4b. manifest-only revert on a copy of the checkout: the Gemfile is
    //     back at its registry declaration, the lock keeps the PATH section.
    //     Bundler takes the gem from the source the Gemfile names, so the
    //     section wires nothing: no statement, with the ledger or without.
    let copy = v.scratch.join("manifest-only-revert");
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::write(copy.join("Gemfile"), v.pristine_gemfile).unwrap();
    std::fs::write(copy.join(lock_name), &lock).unwrap();
    common::fs_tree::copy_tree(&fresh.join(".socket"), &copy.join(".socket"));
    common::fs_tree::copy_tree(v.committed_bundle, &copy.join(".bundle"));
    for f in std::fs::read_dir(&saved).unwrap() {
        let f = f.unwrap();
        std::fs::copy(f.path(), copy.join(".socket/vendor").join(f.file_name())).unwrap();
    }
    for no_verify in [false, true] {
        let mut r = run(VexRun::offline());
        r.no_verify = no_verify;
        let out = run_vex(&bin, &copy, &r);
        assert_eq!(
            out.code,
            Some(1),
            "Gemfile reverted, lock PATH section kept, ledger kept (no_verify={no_verify}): \
             {out}\n{ctx}"
        );
        assert_absent(out.doc.as_ref(), v.purl);
        assert_not_attested(&out.envelope, v.purl, "vendor_unwired");
    }
    let frozen = bundle(&copy, &["install"], true);
    assert!(
        !frozen.status.success(),
        "a frozen install must refuse a lock whose path the Gemfile does not name (bundler {})",
        v.bundler.version
    );
    common::fs_tree::copy_tree(v.committed_bundle, &copy.join(".bundle"));
    let install = bundle(&copy, &["install"], false);
    assert!(
        install.status.success(),
        "unfrozen install over the lock-only pair (bundler {}):\n{}",
        v.bundler.version,
        String::from_utf8_lossy(&install.stderr)
    );
    let relocked = std::fs::read_to_string(copy.join(lock_name)).unwrap();
    assert!(
        !relocked.contains(".socket/vendor/gem/"),
        "bundler must drop the PATH section the Gemfile does not name:\n{relocked}"
    );
    strip_ledgers(&copy);
    let out = run_vex(&bin, &copy, &run(VexRun::online(&api)));
    assert_eq!(
        out.code,
        Some(2),
        "re-resolved from the registry, ledger-less: {out}\n{relocked}"
    );
    assert_absent(out.doc.as_ref(), v.purl);

    // 5. full revert to the registry pair; ledgers + artifact kept.
    restore_ledgers();
    std::fs::write(fresh.join("Gemfile"), v.pristine_gemfile).unwrap();
    std::fs::write(fresh.join(lock_name), v.pristine_lock).unwrap();
    for (offline, no_verify) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut r = run(if offline {
            VexRun::offline()
        } else {
            VexRun::online(&api)
        });
        r.no_verify = no_verify;
        let out = run_vex(&bin, fresh, &r);
        let cell = format!("reverted offline={offline} no_verify={no_verify}");
        assert_eq!(out.code, Some(1), "{cell}: {out}");
        assert_not_attested(&out.envelope, v.purl, "vendor_unwired");
        assert_absent(out.doc.as_ref(), v.purl);
    }
}

// ── the capstone ──────────────────────────────────────────────────────

#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_fresh_checkout_bundle_install_and_revert() {
    let Some(bundler) = gate("direct") else {
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"rack\", \"~> 3.1\"\n",
    )
    .unwrap();

    // Project-local gem home: keeps the host gem environment pristine and is
    // exactly the layout the ruby crawler discovers first.
    let config = bundle(
        &proj,
        &argv(&bundler.config_local_args("path", "vendor/bundle")),
        false,
    );
    if !config.status.success() {
        println!(
            "SKIP e2e_vendor_gem_build: `bundle config set --local path` failed:\n{}",
            String::from_utf8_lossy(&config.stderr)
        );
        return;
    }

    // 1. REAL fixture: bundle install resolves rack from rubygems.org
    //    (network allowed here only; skip when unreachable or the host ruby
    //    is too old for any rack 3.1.x).
    let install = bundle(&proj, &["install"], false);
    if !install.status.success() {
        println!(
            "SKIP e2e_vendor_gem_build: `bundle install` failed (registry unreachable, or \
             host ruby too old for rack ~> 3.1?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }

    let lock_path = proj.join("Gemfile.lock");
    let lock_before = std::fs::read(&lock_path).expect("Gemfile.lock after bundle install");
    let version = locked_gem_version(&String::from_utf8_lossy(&lock_before), DEP)
        .unwrap_or_else(|| panic!("could not read the resolved {DEP} version from Gemfile.lock"));

    // The installed gem dir under bundler's deployment layout.
    let mut ruby = Command::new("ruby");
    ruby.args(["-e", "puts Gem.ruby_api_version"]);
    cache_env::isolate(&mut ruby);
    let api = ruby.output().expect("failed to run ruby");
    assert!(api.status.success(), "ruby api version probe failed");
    let api = String::from_utf8_lossy(&api.stdout).trim().to_string();
    let gem_dir = proj
        .join("vendor/bundle/ruby")
        .join(&api)
        .join("gems")
        .join(format!("{DEP}-{version}"));
    let installed_rb = gem_dir.join("lib/rack.rb");
    let orig = std::fs::read(&installed_rb).expect("installed lib/rack.rb");
    assert!(
        !String::from_utf8_lossy(&orig).contains("SOCKET_PATCH_VENDOR_E2E"),
        "pristine install must not carry the probe constant"
    );

    // 2. Marker patch = the ACTUAL installed bytes + a reopened `module Rack`
    //    defining a probe constant (observable via `require "rack"`).
    let marker = format!(
        "\n# SOCKET-PATCH-VENDOR-E2E-MARKER\nmodule Rack\n  SOCKET_PATCH_VENDOR_E2E = \"{UUID}\"\nend\n"
    );
    let patched: Vec<u8> = [orig.as_slice(), marker.as_bytes()].concat();
    let purl = format!("pkg:gem/{DEP}@{version}");
    stage_patch_with_vuln(&proj, &purl, "lib/rack.rb", &orig, &patched);

    let gemfile_path = proj.join("Gemfile");
    let gemfile_before = std::fs::read(&gemfile_path).unwrap();

    // 3. Vendor (offline: the blob is staged locally → zero network).
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");
    let applied = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "applied" && e["purl"] == purl.as_str())
        .unwrap_or_else(|| panic!("expected an applied event for {purl}: {env}"));
    assert!(
        applied.get("errorCode").is_none(),
        "clean apply event: {applied}"
    );

    // Artifact: patched gem dir + the materialized stub gemspec (a path
    // source needs one) + the informational marker + the committed ledger.
    let copy_rel = format!(".socket/vendor/gem/{UUID}/{DEP}-{version}");
    assert_eq!(
        std::fs::read(proj.join(&copy_rel).join("lib/rack.rb")).unwrap(),
        patched,
        "vendored lib/rack.rb must hold the patched bytes"
    );
    assert!(
        proj.join(&copy_rel)
            .join(format!("{DEP}.gemspec"))
            .is_file(),
        "stub gemspec not materialized into the vendored dir"
    );
    assert!(
        proj.join(format!(
            ".socket/vendor/gem/{UUID}/socket-patch.vendor.json"
        ))
        .is_file(),
        "informational vendor marker missing"
    );
    assert!(
        proj.join(".socket/vendor/state.json").is_file(),
        "vendor ledger missing"
    );

    // The MANDATORY pair edit (a lock-only edit is a silent unpatch on the
    // next plain `bundle install`): Gemfile line → exact pin + `path:`; the
    // lock gains a PATH section (before GEM, relative remote, spec moved
    // over) and the `rack (= <ver>)!` DEPENDENCIES pin.
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    assert!(
        gemfile.contains(&format!(
            "gem \"{DEP}\", \"{version}\", path: \"{copy_rel}\""
        )),
        "Gemfile line not rewritten to the exact-pin + path: form:\n{gemfile}"
    );
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    let path_section = format!("PATH\n  remote: {copy_rel}\n  specs:\n    {DEP} ({version})");
    assert!(
        lock.contains(&path_section),
        "canonical PATH section missing from Gemfile.lock:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\n  {DEP} (= {version})!")),
        "DEPENDENCIES pin `  {DEP} (= {version})!` missing:\n{lock}"
    );
    let path_at = lock.find(&path_section).unwrap();
    let gem_at = lock.find("\nGEM\n").expect("GEM section survives the edit");
    assert!(
        path_at < gem_at,
        "the PATH section must precede GEM (bundler's canonical placement):\n{lock}"
    );

    // 4. VEX (vendored) leg: attest the patch against the committed gem dir
    //    (gem has no product auto-detect, so `--product` is explicit).
    let vex_path = proj.join("out.vex.json");
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vex",
            "--cwd",
            proj.to_str().unwrap(),
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            "pkg:gem/app@1.0.0",
        ],
    );
    assert_eq!(code, 0, "vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "the vendored gem patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    assert!(
        impact.contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {impact}"
    );

    // REGRESSION (#2076): the registry copy the first `bundle install` put
    // in the gem home is a leftover now. Bundler loads the vendored path
    // and installs nothing for rack, so no install replaces that copy. The
    // warning about it must name the copy and a remedy that removes it
    // (`bundle clean`, run below), not a reinstall.
    assert!(
        stderr.contains(&format!("Warning: {purl}: "))
            && stderr.contains(&format!("({})", gem_dir.display()))
            && stderr.contains("`bundle clean` prunes it"),
        "the leftover gem-home copy is named, with remedies that clear it:\n{stderr}"
    );
    assert!(
        !stderr.contains("re-run your package manager"),
        "no install resyncs a vendored gem's leftover:\n{stderr}"
    );

    // 5. FRESH-CHECKOUT PROOF: ONLY the committable files, frozen lock. The
    //    vendored path source is the only provider of rack (the fresh dir
    //    has no vendor/bundle), and the patched constant must be visible at
    //    `require` time from the vendored path.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&gemfile_path, fresh.join("Gemfile")).unwrap();
    std::fs::copy(&lock_path, fresh.join("Gemfile.lock")).unwrap();
    common::fs_tree::copy_tree(&proj.join(".socket"), &fresh.join(".socket"));
    common::fs_tree::copy_tree(&proj.join(".bundle"), &fresh.join(".bundle"));
    assert!(
        !fresh.join("vendor").exists(),
        "fresh checkout must not carry an installed tree (test bug)"
    );

    let lock_wired = std::fs::read(&lock_path).unwrap();
    let ci = bundle(&fresh, &["install"], true);
    assert!(
        ci.status.success(),
        "fresh-checkout frozen `bundle install` must succeed from the vendored path.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    assert_eq!(
        std::fs::read(fresh.join("Gemfile.lock")).unwrap(),
        lock_wired,
        "frozen install must leave the committed Gemfile.lock byte-identical"
    );

    // Runtime proof: rack loads FROM the vendored path and exposes the
    // patched probe constant carrying the patch uuid.
    let probe = bundle(
        &fresh,
        &[
            "exec",
            "ruby",
            "-e",
            "require \"rack\"\n\
             abort \"probe constant missing after require\" unless defined?(Rack::SOCKET_PATCH_VENDOR_E2E)\n\
             puts Rack::SOCKET_PATCH_VENDOR_E2E\n\
             puts $LOADED_FEATURES.grep(%r{/rack\\.rb\\z})",
        ],
        false,
    );
    assert!(
        probe.status.success(),
        "bundle exec runtime probe failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr),
    );
    let probe_out = String::from_utf8_lossy(&probe.stdout).into_owned();
    assert!(
        probe_out.contains(UUID),
        "probe constant must carry the patch uuid:\n{probe_out}"
    );
    assert!(
        probe_out.contains(&format!("{copy_rel}/lib/rack.rb")),
        "rack must be loaded from the vendored path:\n{probe_out}"
    );

    vendored_manifestless_vex_matrix(&Vendored {
        bundler: &bundler,
        fresh: &fresh,
        committed_bundle: &proj.join(".bundle"),
        scratch: &tmp.path().join("vex-scratch"),
        purl: &purl,
        patched: &patched,
        pristine_gemfile: &gemfile_before,
        pristine_lock: &lock_before,
    });

    // 6. Idempotency: a re-run exits 0 and leaves BOTH files byte-stable.
    let gemfile_wired = std::fs::read(&gemfile_path).unwrap();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env2 = parse_json_envelope(&stdout);
    assert_eq!(env2["summary"]["failed"], 0, "re-run must not fail: {env2}");
    assert_eq!(
        std::fs::read(&gemfile_path).unwrap(),
        gemfile_wired,
        "re-vendor must leave the Gemfile byte-identical"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "re-vendor must leave Gemfile.lock byte-identical"
    );

    // #2076, the remedy: `bundle clean` removes the leftover, touches
    // neither file of the pair, and `vex` then has nothing to report. Run
    // on a copy, so the revert below still starts from the tree a user
    // reverts from.
    let cleaned = tmp.path().join("cleaned");
    common::fs_tree::copy_tree(&proj, &cleaned);
    let clean = bundle(&cleaned, &["clean"], false);
    assert!(
        clean.status.success(),
        "`bundle clean` failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&clean.stdout),
        String::from_utf8_lossy(&clean.stderr),
    );
    let cleaned_gem_dir = cleaned.join(gem_dir.strip_prefix(&proj).unwrap());
    let vex_cleaned = || {
        let (code, stdout, stderr) = run_socket(
            &cleaned,
            &[
                "vex",
                "--json",
                "--cwd",
                cleaned.to_str().unwrap(),
                "--output",
                cleaned.join("out.vex.json").to_str().unwrap(),
                "--product",
                "pkg:gem/app@1.0.0",
            ],
        );
        assert_eq!(code, 0, "vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
        let env = parse_json_envelope(&stdout);
        assert_eq!(env["status"], "success", "envelope: {env}");
        env
    };
    let out_of_sync = |env: &serde_json::Value| {
        env["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w["code"] == "vendored_tree_out_of_sync"))
    };
    let ruby_major: u32 = api
        .split('.')
        .next()
        .and_then(|major| major.parse().ok())
        .unwrap_or_else(|| panic!("unparseable ruby api version {api:?}"));
    if bundler.clean_leaves_directories(ruby_major) {
        // #2115: this bundler decides to remove the leftover and cannot
        // delete a non-empty directory on this Ruby (see
        // `clean_leaves_directories`). The two assertions keep this arm from
        // outliving the defect; `vex` keeps warning for as long as the
        // directory is there. Then finish the removal by hand.
        let clean_out = String::from_utf8_lossy(&clean.stdout);
        assert!(
            clean_out.contains(&format!("Removing {DEP} ({version})")),
            "`bundle clean` must name the leftover as stale (bundler {}):\n{clean_out}",
            bundler.version
        );
        assert!(
            cleaned_gem_dir.exists(),
            "bundler {} on Ruby {api} removed {}: `clean_leaves_directories` is out of date",
            bundler.version,
            cleaned_gem_dir.display()
        );
        let env = vex_cleaned();
        assert!(
            out_of_sync(&env),
            "the leftover this `bundle clean` could not delete is still reported: {env}"
        );
        std::fs::remove_dir_all(&cleaned_gem_dir).unwrap();
    } else {
        assert!(
            !cleaned_gem_dir.exists(),
            "`bundle clean` must remove the leftover {} (bundler {}, Ruby {api})",
            cleaned_gem_dir.display(),
            bundler.version
        );
    }
    assert_eq!(
        std::fs::read(cleaned.join("Gemfile.lock")).unwrap(),
        lock_wired,
        "`bundle clean` must leave Gemfile.lock byte-identical"
    );
    let env = vex_cleaned();
    assert!(
        !out_of_sync(&env),
        "nothing is out of sync once the leftover is gone: {env}"
    );

    // 7. REVERT PROOF: both halves of the pair edit byte-restored, artifacts
    //    gone.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_json_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&gemfile_path).unwrap(),
        gemfile_before,
        "revert must restore the Gemfile byte-identical to the pre-vendor snapshot"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "revert must restore Gemfile.lock byte-identical to the pre-vendor snapshot"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
}

/// TRANSITIVE-dep capstone: vendoring a gem the Gemfile never declares
/// (`rack`, pulled in by `rack-test`) appends the managed block + the sorted
/// `rack (= <ver>)!` DEPENDENCIES pin — a wiring shape the direct-dep
/// capstone never produces — and a REAL frozen `bundle install` of a fresh
/// checkout must accept that pair byte-stably, load the patched bytes from
/// the vendored path through the rack-test require chain, and revert must
/// byte-restore both files (managed block gone, DEPENDENCIES entry deleted).
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_transitive_dep_fresh_checkout_and_revert() {
    let Some(bundler) = gate("transitive") else {
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"rack-test\", \"~> 2.1\"\n",
    )
    .unwrap();

    let config = bundle(
        &proj,
        &argv(&bundler.config_local_args("path", "vendor/bundle")),
        false,
    );
    if !config.status.success() {
        println!(
            "SKIP e2e_vendor_gem_build (transitive): `bundle config set --local path` failed:\n{}",
            String::from_utf8_lossy(&config.stderr)
        );
        return;
    }
    // Pin the no-CHECKSUMS lock shape on every host (bundler >= 4 writes a
    // CHECKSUMS section by default; 2.5–3.x never do) — the CHECKSUMS-lock
    // vendoring flavor is covered by docker_e2e_vendor_gem's twin.
    if bundler.at_least(2, 6) {
        let no_ck = bundle(
            &proj,
            &["config", "set", "--local", "lockfile_checksums", "false"],
            false,
        );
        assert!(
            no_ck.status.success(),
            "bundle config set --local lockfile_checksums failed:\n{}",
            String::from_utf8_lossy(&no_ck.stderr)
        );
    }
    let install = bundle(&proj, &["install"], false);
    if !install.status.success() {
        println!(
            "SKIP e2e_vendor_gem_build (transitive): `bundle install` failed (registry \
             unreachable, or host ruby too old for rack-test ~> 2.1?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }

    let lock_path = proj.join("Gemfile.lock");
    let lock_before = std::fs::read(&lock_path).expect("Gemfile.lock after bundle install");
    let lock_before_text = String::from_utf8_lossy(&lock_before).into_owned();
    let version = locked_gem_version(&lock_before_text, DEP)
        .unwrap_or_else(|| panic!("rack-test must resolve rack into Gemfile.lock"));

    // Anti-vacuity: rack really is transitive — undeclared in the Gemfile
    // and absent from the lock's DEPENDENCIES section (which does list
    // `  rack-test (~> 2.1)`, so the probe pins the exact token).
    let gemfile_path = proj.join("Gemfile");
    let gemfile_before = std::fs::read(&gemfile_path).unwrap();
    assert!(
        !String::from_utf8_lossy(&gemfile_before).contains("\"rack\""),
        "fixture bug: rack must not be Gemfile-declared"
    );
    assert!(
        !lock_before_text.contains("\nCHECKSUMS\n"),
        "fixture bug: this capstone pins the no-CHECKSUMS lock shape: {lock_before_text}"
    );
    let deps_section = lock_before_text
        .split("DEPENDENCIES\n")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("lock has a DEPENDENCIES section");
    assert!(
        !deps_section
            .lines()
            .any(|l| l == "  rack" || l.starts_with("  rack (") || l.starts_with("  rack!")),
        "fixture bug: rack must not appear in DEPENDENCIES: {deps_section}"
    );

    // The installed transitive gem, marker patch on its ACTUAL bytes.
    let mut ruby = Command::new("ruby");
    ruby.args(["-e", "puts Gem.ruby_api_version"]);
    cache_env::isolate(&mut ruby);
    let api = ruby.output().expect("failed to run ruby");
    assert!(api.status.success(), "ruby api version probe failed");
    let api = String::from_utf8_lossy(&api.stdout).trim().to_string();
    let installed_rb = proj
        .join("vendor/bundle/ruby")
        .join(&api)
        .join("gems")
        .join(format!("{DEP}-{version}"))
        .join("lib/rack.rb");
    let orig = std::fs::read(&installed_rb).expect("installed lib/rack.rb");
    assert!(
        !String::from_utf8_lossy(&orig).contains("SOCKET_PATCH_VENDOR_E2E"),
        "pristine install must not carry the probe constant"
    );
    let marker = format!(
        "\n# SOCKET-PATCH-VENDOR-E2E-MARKER\nmodule Rack\n  SOCKET_PATCH_VENDOR_E2E = \"{UUID}\"\nend\n"
    );
    let patched: Vec<u8> = [orig.as_slice(), marker.as_bytes()].concat();
    let purl = format!("pkg:gem/{DEP}@{version}");
    stage_patch_with_vuln(&proj, &purl, "lib/rack.rb", &orig, &patched);

    // Vendor (offline). The transitive branch appends the managed block.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");

    // The appended managed block, byte-exact (hand-pinned marker lines — the
    // block delimits what revert may delete, so its shape is contract).
    let copy_rel = format!(".socket/vendor/gem/{UUID}/{DEP}-{version}");
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    let expected_gemfile = format!(
        "{}# >>> socket-patch vendor (managed) >>>\ngem \"{DEP}\", \"{version}\", \
         path: \"{copy_rel}\", require: false\n# <<< socket-patch vendor (managed) <<<\n",
        String::from_utf8_lossy(&gemfile_before)
    );
    assert_eq!(
        gemfile, expected_gemfile,
        "transitive vendor must append exactly the managed block"
    );

    // The lock pair: canonical PATH section before GEM, and the DEPENDENCIES
    // pin inserted at bundler's sorted position (rack before rack-test).
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.contains(&format!(
            "PATH\n  remote: {copy_rel}\n  specs:\n    {DEP} ({version})"
        )),
        "canonical PATH section missing:\n{lock}"
    );
    assert!(
        lock.contains(&format!(
            "DEPENDENCIES\n  {DEP} (= {version})!\n  rack-test (~> 2.1)\n"
        )),
        "DEPENDENCIES pin must insert at bundler's sorted position:\n{lock}"
    );

    // FRESH-CHECKOUT PROOF: committable files only, frozen install (bundler
    // validates the Gemfile↔lock dependency sets — an unsorted or malformed
    // insert fails here), byte-stable lock, patched bytes reached THROUGH the
    // rack-test require chain.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&gemfile_path, fresh.join("Gemfile")).unwrap();
    std::fs::copy(&lock_path, fresh.join("Gemfile.lock")).unwrap();
    common::fs_tree::copy_tree(&proj.join(".socket"), &fresh.join(".socket"));
    common::fs_tree::copy_tree(&proj.join(".bundle"), &fresh.join(".bundle"));
    assert!(
        !fresh.join("vendor").exists(),
        "fresh checkout must not carry an installed tree (test bug)"
    );

    let lock_wired = std::fs::read(&lock_path).unwrap();
    let ci = bundle(&fresh, &["install"], true);
    assert!(
        ci.status.success(),
        "fresh-checkout frozen `bundle install` must accept the managed-block pair.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    assert_eq!(
        std::fs::read(fresh.join("Gemfile.lock")).unwrap(),
        lock_wired,
        "frozen install must leave the committed Gemfile.lock byte-identical"
    );

    // BOOT PROOF (#2084): `Bundler.require` is what an app runs at boot. It
    // loads the declared `rack-test`, and must not load `rack`, which the
    // Gemfile did not declare before the managed block: `rack/test` leaves
    // `lib/rack.rb` (and with it the probe constant) unloaded, so only an
    // auto-require of the block's own declaration defines it.
    let boot = bundle(
        &fresh,
        &[
            "exec",
            "ruby",
            "-e",
            "require \"bundler/setup\"\n\
             Bundler.require(:default)\n\
             abort \"rack-test was not required at boot\" unless defined?(Rack::Test)\n\
             abort \"Bundler.require loaded the vendored transitive gem\" if defined?(Rack::SOCKET_PATCH_VENDOR_E2E)\n\
             abort \"lib/rack.rb loaded at boot\" if $LOADED_FEATURES.grep(%r{/rack\\.rb\\z}).any?",
        ],
        false,
    );
    assert!(
        boot.status.success(),
        "`Bundler.require` must not load a gem the Gemfile did not declare.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&boot.stdout),
        String::from_utf8_lossy(&boot.stderr),
    );

    // `require "rack/test"` proves the direct dep still resolves alongside
    // the vendored transitive; it does not itself load `lib/rack.rb`, so the
    // marker is probed through an explicit `require "rack"` in the same VM.
    let probe = bundle(
        &fresh,
        &[
            "exec",
            "ruby",
            "-e",
            "require \"rack/test\"\n\
             require \"rack\"\n\
             abort \"probe constant missing after require\" unless defined?(Rack::SOCKET_PATCH_VENDOR_E2E)\n\
             puts Rack::SOCKET_PATCH_VENDOR_E2E\n\
             puts $LOADED_FEATURES.grep(%r{/rack\\.rb\\z})",
        ],
        false,
    );
    assert!(
        probe.status.success(),
        "bundle exec runtime probe failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr),
    );
    let probe_out = String::from_utf8_lossy(&probe.stdout).into_owned();
    assert!(
        probe_out.contains(UUID),
        "probe constant must carry the patch uuid:\n{probe_out}"
    );
    assert!(
        probe_out.contains(&format!("{copy_rel}/lib/rack.rb")),
        "rack must be loaded from the vendored path via rack-test:\n{probe_out}"
    );

    vendored_manifestless_vex_matrix(&Vendored {
        bundler: &bundler,
        fresh: &fresh,
        committed_bundle: &proj.join(".bundle"),
        scratch: &tmp.path().join("vex-scratch"),
        purl: &purl,
        patched: &patched,
        pristine_gemfile: &gemfile_before,
        pristine_lock: &lock_before,
    });

    // Idempotency: a re-run leaves both files byte-identical (a second
    // managed block or a duplicated DEPENDENCIES pin breaks bundler).
    let gemfile_wired = std::fs::read(&gemfile_path).unwrap();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env2 = parse_json_envelope(&stdout);
    assert_eq!(env2["summary"]["failed"], 0, "re-run must not fail: {env2}");
    assert_eq!(
        std::fs::read(&gemfile_path).unwrap(),
        gemfile_wired,
        "re-vendor must leave the Gemfile byte-identical"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "re-vendor must leave Gemfile.lock byte-identical"
    );

    // REVERT PROOF: the managed block and the DEPENDENCIES pin are deletions
    // (no pre-vendor original exists for either) — both files must come back
    // byte-identical to the pre-vendor snapshots.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_json_envelope(&stdout);
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&gemfile_path).unwrap(),
        gemfile_before,
        "revert must restore the Gemfile byte-identical (managed block gone)"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "revert must restore Gemfile.lock byte-identical (PATH + pin gone)"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
}

/// GET-DRIVEN TWIN of the direct-dep capstone: `get <uuid> --mode vendored`
/// (v3.6, the per-advisory selector) must leave the same committable state
/// as a plain `vendor` run — the ledger's detached entry (no manifest), `.socket/vendor/` artifact +
/// ledger, the mandatory Gemfile/lock pair edit — with NO `.socket/blobs`
/// (get's vendored download phase holds content in memory) and get's
/// envelope nesting the vendor Envelope (and dropping `applied`). The patch
/// record arrives THROUGH get from a wiremock `view/{uuid}` carrying REAL
/// git-blob hashes of the actual installed bytes plus inline `blobContent`;
/// `--vendor-source build` keeps the artifact build local so that mock is
/// the only API surface. Proof is the model capstone's fresh-checkout leg
/// (frozen install, byte-stable lock, runtime require probe); the revert
/// half stays with the vendor-driven capstone.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
async fn gem_get_uuid_vendored_fresh_checkout_bundle_install() {
    let Some(bundler) = gate("get-vendored") else {
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"rack\", \"~> 3.1\"\n",
    )
    .unwrap();

    let config = bundle(
        &proj,
        &argv(&bundler.config_local_args("path", "vendor/bundle")),
        false,
    );
    if !config.status.success() {
        println!(
            "SKIP e2e_vendor_gem_build (get-vendored): `bundle config set --local path` \
             failed:\n{}",
            String::from_utf8_lossy(&config.stderr)
        );
        return;
    }

    // 1. REAL fixture: bundle install resolves rack from rubygems.org
    //    (network allowed here only; skip when unreachable).
    let install = bundle(&proj, &["install"], false);
    if !install.status.success() {
        println!(
            "SKIP e2e_vendor_gem_build (get-vendored): `bundle install` failed (registry \
             unreachable, or host ruby too old for rack ~> 3.1?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }

    let lock_path = proj.join("Gemfile.lock");
    let lock_before = std::fs::read(&lock_path).expect("Gemfile.lock after bundle install");
    let version = locked_gem_version(&String::from_utf8_lossy(&lock_before), DEP)
        .unwrap_or_else(|| panic!("could not read the resolved {DEP} version from Gemfile.lock"));

    // The installed gem dir under bundler's deployment layout.
    let mut ruby = Command::new("ruby");
    ruby.args(["-e", "puts Gem.ruby_api_version"]);
    cache_env::isolate(&mut ruby);
    let api = ruby.output().expect("failed to run ruby");
    assert!(api.status.success(), "ruby api version probe failed");
    let api = String::from_utf8_lossy(&api.stdout).trim().to_string();
    let installed_rb = proj
        .join("vendor/bundle/ruby")
        .join(&api)
        .join("gems")
        .join(format!("{DEP}-{version}"))
        .join("lib/rack.rb");
    let orig = std::fs::read(&installed_rb).expect("installed lib/rack.rb");
    assert!(
        !String::from_utf8_lossy(&orig).contains("SOCKET_PATCH_VENDOR_E2E"),
        "pristine install must not carry the probe constant"
    );

    // 2. Marker patch on the ACTUAL installed bytes — served by the MOCK
    //    API (view with real hashes + inline blobContent) instead of a
    //    hand-staged manifest: get is the component under test, so the
    //    record must arrive through it.
    let marker = format!(
        "\n# SOCKET-PATCH-VENDOR-E2E-MARKER\nmodule Rack\n  SOCKET_PATCH_VENDOR_E2E = \"{UUID}\"\nend\n"
    );
    let patched: Vec<u8> = [orig.as_slice(), marker.as_bytes()].concat();
    let purl = format!("pkg:gem/{DEP}@{version}");

    let server = MockServer::start().await;
    let view = serde_json::json!({
        "uuid": UUID,
        "purl": purl,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": {
            "lib/rack.rb": {
                "beforeHash": git_sha256(&orig),
                "afterHash": git_sha256(&patched),
                "blobContent": b64(&patched),
            }
        },
        "vulnerabilities": { GHSA: {
            "cves": ["CVE-2026-55555"],
            "summary": "gem capstone vex vuln",
            "severity": "high",
            "description": "d",
        }},
        "description": "capstone marker patch",
        "license": "MIT",
        "tier": "free",
    });
    prebuilt_common::mount_view_from_source(
        &server,
        &view,
        None,
        installed_rb.parent().and_then(Path::parent),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view.clone()))
        .mount(&server)
        .await;
    let api_url = server.uri();

    let gemfile_path = proj.join("Gemfile");
    let gemfile_before = std::fs::read(&gemfile_path).unwrap();

    // 3. get <uuid> --mode vendored: record save + scan's whole-manifest
    //    vendor step in one command. The fixture service publishes the full
    //    installed gem with its patched member, including unmodified files.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "get",
            UUID,
            "--mode",
            "vendored",
            "--json",
            "--yes",
            "--vendor-source",
            "service",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &api_url,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    assert_eq!(
        code, 0,
        "get --mode vendored failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["command"], "get", "envelope: {env}");
    assert_eq!(env["summary"]["downloaded"], 1, "envelope: {env}");
    // get's vendored envelope (CLI_CONTRACT.md "get --mode and installed
    // narrowing"): `applied` is dropped (structurally zero — nothing is
    // applied in place), and the vendor Envelope nests under "vendor".
    assert!(
        env.get("applied").is_none(),
        "get --mode vendored must drop the `applied` key: {env}"
    );
    assert_eq!(env["events"][0]["action"], "downloaded", "envelope: {env}");
    assert_eq!(env["events"][0]["purl"], purl.as_str(), "envelope: {env}");
    assert_eq!(env["events"][0]["uuid"], UUID, "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no vendor failures: {env}");
    let applied = env["events"]
        .as_array()
        .expect("vendor events array")
        .iter()
        .find(|e| e["action"] == "applied" && e["purl"] == purl.as_str())
        .unwrap_or_else(|| panic!("expected an applied vendor event for {purl}: {env}"));
    assert!(
        applied.get("errorCode").is_none(),
        "clean vendor event: {applied}"
    );

    // Persistence: the ledger's detached entry records the patch; NO
    // manifest and NO blobs land on disk (the committed artifact IS the
    // patch — parity with scan --mode vendored).
    assert!(
        !proj.join(".socket/manifest.json").exists(),
        "get --mode vendored must NOT write the manifest (the ledger is the record)"
    );
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(proj.join(".socket/vendor/state.json"))
            .expect("vendor ledger missing"),
    )
    .unwrap();
    assert_eq!(
        state["entries"][purl.as_str()]["uuid"],
        UUID,
        "the ledger must record the vendored patch: {state}"
    );
    assert_eq!(
        state["entries"][purl.as_str()]["detached"],
        true,
        "a get --mode vendored entry is detached: {state}"
    );
    assert!(
        !proj.join(".socket/blobs").exists(),
        "get --mode vendored must NOT persist blobs"
    );

    // Artifact: patched gem dir + the materialized stub gemspec + the
    // committed ledger — identical to what a plain `vendor` run commits.
    let copy_rel = format!(".socket/vendor/gem/{UUID}/{DEP}-{version}");
    assert_eq!(
        std::fs::read(proj.join(&copy_rel).join("lib/rack.rb")).unwrap(),
        patched,
        "vendored lib/rack.rb must hold the patched bytes"
    );
    assert!(
        proj.join(&copy_rel)
            .join(format!("{DEP}.gemspec"))
            .is_file(),
        "stub gemspec not materialized into the vendored dir"
    );
    assert!(
        proj.join(".socket/vendor/state.json").is_file(),
        "vendor ledger missing"
    );

    // The MANDATORY pair edit, exactly as the vendor-driven capstone pins
    // it: Gemfile line → exact pin + `path:`; the lock gains the canonical
    // PATH section (before GEM) and the `rack (= <ver>)!` DEPENDENCIES pin.
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    assert!(
        gemfile.contains(&format!(
            "gem \"{DEP}\", \"{version}\", path: \"{copy_rel}\""
        )),
        "Gemfile line not rewritten to the exact-pin + path: form:\n{gemfile}"
    );
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    let path_section = format!("PATH\n  remote: {copy_rel}\n  specs:\n    {DEP} ({version})");
    assert!(
        lock.contains(&path_section),
        "canonical PATH section missing from Gemfile.lock:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\n  {DEP} (= {version})!")),
        "DEPENDENCIES pin `  {DEP} (= {version})!` missing:\n{lock}"
    );
    let path_at = lock.find(&path_section).unwrap();
    let gem_at = lock.find("\nGEM\n").expect("GEM section survives the edit");
    assert!(
        path_at < gem_at,
        "the PATH section must precede GEM (bundler's canonical placement):\n{lock}"
    );

    // FRESH-CHECKOUT PROOF (the model capstone's leg): ONLY the committable
    // files, frozen lock. The vendored path source is the only provider of
    // rack, and the patched constant must be visible at `require` time.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&gemfile_path, fresh.join("Gemfile")).unwrap();
    std::fs::copy(&lock_path, fresh.join("Gemfile.lock")).unwrap();
    common::fs_tree::copy_tree(&proj.join(".socket"), &fresh.join(".socket"));
    common::fs_tree::copy_tree(&proj.join(".bundle"), &fresh.join(".bundle"));
    assert!(
        !fresh.join("vendor").exists(),
        "fresh checkout must not carry an installed tree (test bug)"
    );

    let lock_wired = std::fs::read(&lock_path).unwrap();
    let ci = bundle(&fresh, &["install"], true);
    assert!(
        ci.status.success(),
        "fresh-checkout frozen `bundle install` must succeed from the vendored path.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    assert_eq!(
        std::fs::read(fresh.join("Gemfile.lock")).unwrap(),
        lock_wired,
        "frozen install must leave the committed Gemfile.lock byte-identical"
    );

    // Runtime proof: rack loads FROM the vendored path and exposes the
    // patched probe constant carrying the patch uuid.
    let probe = bundle(
        &fresh,
        &[
            "exec",
            "ruby",
            "-e",
            "require \"rack\"\n\
             abort \"probe constant missing after require\" unless defined?(Rack::SOCKET_PATCH_VENDOR_E2E)\n\
             puts Rack::SOCKET_PATCH_VENDOR_E2E\n\
             puts $LOADED_FEATURES.grep(%r{/rack\\.rb\\z})",
        ],
        false,
    );
    assert!(
        probe.status.success(),
        "bundle exec runtime probe failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr),
    );
    let probe_out = String::from_utf8_lossy(&probe.stdout).into_owned();
    assert!(
        probe_out.contains(UUID),
        "probe constant must carry the patch uuid:\n{probe_out}"
    );
    assert!(
        probe_out.contains(&format!("{copy_rel}/lib/rack.rb")),
        "rack must be loaded from the vendored path:\n{probe_out}"
    );

    // On a plain thread: the matrix's PatchApi runs its own runtime, which
    // cannot be started (or dropped) from inside this test's async context.
    std::thread::scope(|scope| {
        scope.spawn(|| {
            vendored_manifestless_vex_matrix(&Vendored {
                bundler: &bundler,
                fresh: &fresh,
                committed_bundle: &proj.join(".bundle"),
                scratch: &tmp.path().join("vex-scratch"),
                purl: &purl,
                patched: &patched,
                pristine_gemfile: &gemfile_before,
                pristine_lock: &lock_before,
            })
        });
    });

    // ROLLBACK (#2214): the gem was only ever vendored, so Bundler's own
    // install in `vendor/bundle` is still the upstream build. Once the
    // pair is restored no patched byte is left anywhere, and rollback
    // must not name a reinstall.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "rollback",
            "--yes",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &api_url,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    assert_eq!(
        code, 0,
        "rollback failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        std::fs::read(&gemfile_path).unwrap(),
        gemfile_before,
        "rollback must restore the Gemfile byte for byte"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "rollback must restore Gemfile.lock byte for byte"
    );
    assert_eq!(
        std::fs::read(&installed_rb).unwrap(),
        orig,
        "the installed gem was upstream all along"
    );
    let reinstall: Vec<&serde_json::Value> = env["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["code"] == "reinstall_required")
        .collect();
    assert!(
        reinstall.is_empty(),
        "nothing is left to reinstall after an only-vendored gem's rollback: {env}"
    );
}

/// A real `rack ~> 3.1` project installed into `vendor/bundle`, with a
/// marker patch for the installed rack staged under `.socket/`. `None` =
/// skip (message already printed).
fn staged_rack_project(
    tag: &str,
) -> Option<(tempfile::TempDir, PathBuf, bundler_e2e::Bundler, String)> {
    let bundler = gate(tag)?;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"rack\", \"~> 3.1\"\n",
    )
    .unwrap();
    let config = bundle(
        &proj,
        &argv(&bundler.config_local_args("path", "vendor/bundle")),
        false,
    );
    let install = config
        .status
        .success()
        .then(|| bundle(&proj, &["install"], false));
    if !install.as_ref().is_some_and(|i| i.status.success()) {
        println!("SKIP e2e_vendor_gem_build ({tag}): fixture `bundle install` failed");
        return None;
    }
    let lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
    let version = locked_gem_version(&lock, DEP).expect("resolved rack version");
    let mut ruby = Command::new("ruby");
    ruby.args(["-e", "puts Gem.ruby_api_version"]);
    cache_env::isolate(&mut ruby);
    let api = ruby.output().expect("failed to run ruby");
    let api = String::from_utf8_lossy(&api.stdout).trim().to_string();
    let installed_rb = proj
        .join("vendor/bundle/ruby")
        .join(&api)
        .join("gems")
        .join(format!("{DEP}-{version}"))
        .join("lib/rack.rb");
    let orig = std::fs::read(&installed_rb).expect("installed lib/rack.rb");
    let patched: Vec<u8> = [orig.as_slice(), b"\n# SOCKET-PATCH-VENDOR-E2E-MARKER\n"].concat();
    let purl = format!("pkg:gem/{DEP}@{version}");
    stage_patch_with_vuln(&proj, &purl, "lib/rack.rb", &orig, &patched);
    Some((tmp, proj, bundler, purl))
}

/// Run `vendor` on a project whose manifest choice vendored mode cannot
/// follow (`loaded` is what the host bundler loads), and assert the refusal: a `gemfile_not_loaded` failure for the
/// gem, and every manifest and lock byte-untouched.
fn assert_vendor_refuses_unloaded_gemfile(proj: &Path, purl: &str, loaded: &str, files: &[&str]) {
    // The premise: the host bundler loads `loaded`.
    let probe = bundle(
        proj,
        &["exec", "ruby", "-e", "puts Bundler.default_gemfile"],
        false,
    );
    assert!(
        String::from_utf8_lossy(&probe.stdout)
            .trim()
            .ends_with(&format!("/{loaded}")),
        "bundler must load {loaded} (test premise):\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    let before: Vec<Vec<u8>> = files
        .iter()
        .map(|f| std::fs::read(proj.join(f)).unwrap())
        .collect();
    let (code, stdout, stderr) = run_socket(
        proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_ne!(
        code, 0,
        "vendor must not succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 0, "nothing vendored: {env}");
    let event = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["purl"] == purl)
        .unwrap_or_else(|| panic!("an event for {purl}: {env}"));
    assert_eq!(event["errorCode"], "gemfile_not_loaded", "event: {event}");
    for (file, before) in files.iter().zip(before) {
        assert_eq!(
            std::fs::read(proj.join(file)).unwrap(),
            before,
            "{file} must be byte-untouched"
        );
    }
    assert!(
        !proj.join(".socket/vendor/gem").exists(),
        "no vendored copy is written"
    );
}

/// #341: a `gems.rb` / `gems.locked` twin beside the Gemfile pair is what
/// bundler loads. Vendor used to wire the ignored Gemfile, exit 0, and
/// leave bundler installing upstream rack; it must refuse before any write.
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_refuses_a_gems_rb_twin() {
    let Some((_tmp, proj, bundler, purl)) = staged_rack_project("gems.rb twin") else {
        return;
    };
    std::fs::copy(proj.join("Gemfile"), proj.join("gems.rb")).unwrap();
    std::fs::copy(proj.join("Gemfile.lock"), proj.join("gems.locked")).unwrap();
    // bundler >= 2 loads gems.rb; 1.x still reads the Gemfile first. The
    // twin is refused either way (vendor cannot tell which bundler runs).
    let loaded = if bundler.at_least(2, 0) {
        "gems.rb"
    } else {
        "Gemfile"
    };
    assert_vendor_refuses_unloaded_gemfile(
        &proj,
        &purl,
        loaded,
        &["Gemfile", "Gemfile.lock", "gems.rb", "gems.locked"],
    );
}

/// #390: `bundle config set --local gemfile Gemfile.next` (the dual-boot
/// layout) makes bundler load `Gemfile.next`. Vendor used to wire the
/// ignored Gemfile; it must refuse before any write.
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_refuses_a_bundle_gemfile_dual_boot() {
    let Some((_tmp, proj, bundler, purl)) = staged_rack_project("dual boot") else {
        return;
    };
    std::fs::copy(proj.join("Gemfile"), proj.join("Gemfile.next")).unwrap();
    std::fs::copy(proj.join("Gemfile.lock"), proj.join("Gemfile.next.lock")).unwrap();
    let cfg = bundle(
        &proj,
        &argv(&bundler.config_local_args("gemfile", "Gemfile.next")),
        false,
    );
    assert!(cfg.status.success(), "bundle config set --local gemfile");
    assert_vendor_refuses_unloaded_gemfile(
        &proj,
        &purl,
        "Gemfile.next",
        &[
            "Gemfile",
            "Gemfile.lock",
            "Gemfile.next",
            "Gemfile.next.lock",
        ],
    );
}

/// #482: a direct dependency declared through `eval_gemfile` is invisible to
/// the Gemfile line grammar. Vendor used to treat it as transitive, append a
/// managed `path:` declaration, exit 0, and leave every `bundle install`
/// failing on the duplicate; it must refuse before any write.
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_refuses_an_eval_gemfile_direct_dep() {
    let Some((_tmp, proj, _bundler, purl)) = staged_rack_project("eval_gemfile") else {
        return;
    };
    std::fs::write(proj.join("Gemfile.common"), "gem \"rack\", \"~> 3.1\"\n").unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        "source \"https://rubygems.org\"\n\neval_gemfile \"Gemfile.common\"\n",
    )
    .unwrap();
    let relock = bundle(&proj, &["install"], false);
    assert!(
        relock.status.success(),
        "the eval_gemfile layout installs (test premise):\n{}",
        String::from_utf8_lossy(&relock.stderr)
    );
    let files = ["Gemfile", "Gemfile.common", "Gemfile.lock"];
    let before: Vec<Vec<u8>> = files
        .iter()
        .map(|f| std::fs::read(proj.join(f)).unwrap())
        .collect();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_ne!(
        code, 0,
        "vendor must not succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 0, "nothing vendored: {env}");
    let event = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["purl"] == purl)
        .unwrap_or_else(|| panic!("an event for {purl}: {env}"));
    assert_eq!(
        event["errorCode"], "gemfile_declaration_not_editable",
        "event: {event}"
    );
    for (file, before) in files.iter().zip(before) {
        assert_eq!(
            std::fs::read(proj.join(file)).unwrap(),
            before,
            "{file} must be byte-untouched"
        );
    }
    assert!(
        !proj.join(".socket/vendor/gem").exists(),
        "no vendored copy is written"
    );
    for frozen in [false, true] {
        let install = bundle(&proj, &["install"], frozen);
        assert!(
            install.status.success(),
            "bundle install (frozen: {frozen}) must still succeed:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
    }

    // #2151: the refusal names its way out, and following it works. The
    // literal line takes the hidden declaration's place: left next to it,
    // the vendored pin would be a second declaration that differs, which
    // bundler refuses.
    let error = event["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(
            "one literal `gem \"rack\"` line in the Gemfile, in place of any other `gem` call \
             that declares it"
        ) && error.contains("`--mode agent`"),
        "the refusal names its ways out: {event}"
    );
    assert!(
        !error.contains("--mode hosted"),
        "hosted mode refuses this gem for the same reason: {event}"
    );
    std::fs::write(proj.join("Gemfile.common"), "# shared gems\n").unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"rack\", \"~> 3.1\"\neval_gemfile \"Gemfile.common\"\n",
    )
    .unwrap();
    let relock = bundle(&proj, &["install"], false);
    assert!(
        relock.status.success(),
        "the Gemfile installs with the remedy followed (test premise):\n{}",
        String::from_utf8_lossy(&relock.stderr)
    );
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "vendor failed with the remedy followed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(parse_json_envelope(&stdout)["summary"]["applied"], 1);
    let install = bundle(&proj, &["install"], true);
    assert!(
        install.status.success(),
        "frozen install of the vendored pair failed:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
}

/// A static `file://` rubygems source serving one empty gem,
/// `aaa-internal 1.0.0`. It writes the full-index files bundler reads from
/// a file remote (`specs.4.8.gz`, the quick gemspec, the `.gem`), so it
/// works without `gem generate_index` (no longer bundled with RubyGems).
fn private_gem_source(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let script = r#"
require "rubygems/package"
require "zlib"
require "fileutils"
spec = Gem::Specification.new do |s|
  s.name = "aaa-internal"
  s.version = "1.0.0"
  s.summary = "fixture"
  s.authors = ["fixture"]
  s.files = []
end
FileUtils.mkdir_p(["gems", "quick/Marshal.4.8"])
file = Gem::Package.build(spec)
FileUtils.mv(file, "gems/#{file}")
tuple = [[spec.name, spec.version, "ruby"]]
{ "specs.4.8.gz" => tuple, "latest_specs.4.8.gz" => tuple, "prerelease_specs.4.8.gz" => [] }.each do |f, v|
  Zlib::GzipWriter.open(f) { |gz| gz.write(Marshal.dump(v)) }
end
File.binwrite("quick/Marshal.4.8/#{spec.full_name}.gemspec.rz", Zlib::Deflate.deflate(Marshal.dump(spec)))
"#;
    let mut ruby = Command::new("ruby");
    ruby.args(["-e", script]).current_dir(dir);
    cache_env::isolate(&mut ruby);
    let out = ruby.output().expect("failed to run ruby");
    assert!(
        out.status.success(),
        "building the private gem source failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// #779: a Gemfile with a second rubygems source. Bundler 2.2+ writes one
/// GEM section per source, sorted by remote, so the `file://` source comes
/// first and rack sits in the second GEM section. Vendor used to fail with
/// "GEM specs has no entry". It must wire rack so a fresh frozen install
/// loads the patched copy, and `vendor --revert` must put rack back into
/// its own section, restoring the lock byte for byte.
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_second_gem_section_fresh_checkout_and_revert() {
    let Some(bundler) = gate("second GEM section") else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("private-gems");
    private_gem_source(&repo);
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let gemfile_text = format!(
        "source \"https://rubygems.org\"\n\ngem \"rack\", \"~> 3.1\"\n\nsource \"file://{}\" do\n  gem \"aaa-internal\"\nend\n",
        repo.display()
    );
    std::fs::write(proj.join("Gemfile"), &gemfile_text).unwrap();
    let config = bundle(
        &proj,
        &argv(&bundler.config_local_args("path", "vendor/bundle")),
        false,
    );
    let install = config
        .status
        .success()
        .then(|| bundle(&proj, &["install"], false));
    if !install.as_ref().is_some_and(|i| i.status.success()) {
        println!(
            "SKIP e2e_vendor_gem_build (second GEM section): fixture `bundle install` failed:\n{}",
            install
                .map(|i| String::from_utf8_lossy(&i.stderr).into_owned())
                .unwrap_or_default()
        );
        return;
    }
    let lock_path = proj.join("Gemfile.lock");
    let gemfile_path = proj.join("Gemfile");
    let lock_before = std::fs::read(&lock_path).unwrap();
    let gemfile_before = std::fs::read(&gemfile_path).unwrap();
    let lock_text = String::from_utf8_lossy(&lock_before).into_owned();
    let version = locked_gem_version(&lock_text, DEP).expect("resolved rack version");
    if bundler.at_least(2, 2) {
        // The premise: rack is NOT in the first GEM section. (Bundler
        // <= 2.1 merges every rubygems remote into one GEM section; the
        // round trip below must hold on that layout too.)
        let sections: Vec<&str> = lock_text
            .split("\n\n")
            .filter(|s| s.starts_with("GEM\n"))
            .collect();
        let spec = format!("\n    {DEP} ({version})");
        assert!(
            sections.len() == 2 && !sections[0].contains(&spec) && sections[1].contains(&spec),
            "rack must sit in the second of two GEM sections (test premise):\n{lock_text}"
        );
    }

    let mut ruby = Command::new("ruby");
    ruby.args(["-e", "puts Gem.ruby_api_version"]);
    cache_env::isolate(&mut ruby);
    let api = ruby.output().expect("failed to run ruby");
    let api = String::from_utf8_lossy(&api.stdout).trim().to_string();
    let installed_rb = proj
        .join("vendor/bundle/ruby")
        .join(&api)
        .join("gems")
        .join(format!("{DEP}-{version}"))
        .join("lib/rack.rb");
    let orig = std::fs::read(&installed_rb).expect("installed lib/rack.rb");
    let marker = format!(
        "\n# SOCKET-PATCH-VENDOR-E2E-MARKER\nmodule Rack\n  SOCKET_PATCH_VENDOR_E2E = \"{UUID}\"\nend\n"
    );
    let patched: Vec<u8> = [orig.as_slice(), marker.as_bytes()].concat();
    let purl = format!("pkg:gem/{DEP}@{version}");
    stage_patch_with_vuln(&proj, &purl, "lib/rack.rb", &orig, &patched);

    let vendor_args = [
        "vendor",
        "--json",
        "--offline",
        "--cwd",
        proj.to_str().unwrap(),
    ];
    let (code, stdout, stderr) = run_socket(&proj, &vendor_args);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");

    let copy_rel = format!(".socket/vendor/gem/{UUID}/{DEP}-{version}");
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.contains(&format!(
            "PATH\n  remote: {copy_rel}\n  specs:\n    {DEP} ({version})"
        )),
        "canonical PATH section missing from Gemfile.lock:\n{lock}"
    );
    assert!(
        lock.contains("    aaa-internal (1.0.0)"),
        "the private source's spec stays in its GEM section:\n{lock}"
    );

    // Fresh checkout: only the committable files, frozen install, and rack
    // loads the patched bytes from the vendored path.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&gemfile_path, fresh.join("Gemfile")).unwrap();
    std::fs::copy(&lock_path, fresh.join("Gemfile.lock")).unwrap();
    common::fs_tree::copy_tree(&proj.join(".socket"), &fresh.join(".socket"));
    common::fs_tree::copy_tree(&proj.join(".bundle"), &fresh.join(".bundle"));
    let lock_wired = std::fs::read(&lock_path).unwrap();
    let ci = bundle(&fresh, &["install"], true);
    assert!(
        ci.status.success(),
        "fresh-checkout frozen `bundle install` must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    assert_eq!(
        std::fs::read(fresh.join("Gemfile.lock")).unwrap(),
        lock_wired,
        "frozen install must leave the committed Gemfile.lock byte-identical"
    );
    let probe = bundle(
        &fresh,
        &[
            "exec",
            "ruby",
            "-e",
            "require \"rack\"\n\
             abort \"probe constant missing after require\" unless defined?(Rack::SOCKET_PATCH_VENDOR_E2E)\n\
             puts $LOADED_FEATURES.grep(%r{/rack\\.rb\\z})",
        ],
        false,
    );
    assert!(
        probe.status.success(),
        "bundle exec runtime probe failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr),
    );
    assert!(
        String::from_utf8_lossy(&probe.stdout).contains(&format!("{copy_rel}/lib/rack.rb")),
        "rack must be loaded from the vendored path:\n{}",
        String::from_utf8_lossy(&probe.stdout)
    );

    // Idempotent re-run.
    let (code, stdout, stderr) = run_socket(&proj, &vendor_args);
    assert_eq!(
        code, 0,
        "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(std::fs::read(&lock_path).unwrap(), lock_wired);

    // Revert: the spec goes back into the second GEM section.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_json_envelope(&stdout);
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&gemfile_path).unwrap(),
        gemfile_before,
        "revert must restore the Gemfile byte for byte"
    );
    assert_eq!(
        String::from_utf8(std::fs::read(&lock_path).unwrap()).unwrap(),
        lock_text,
        "revert must restore Gemfile.lock byte for byte"
    );
    assert!(!proj.join(".socket/vendor").exists());
}

/// #847: a declaration whose version comes from a splat, a method call or
/// a constant. Vendor used to carry that positional argument after the
/// inserted `path:` keyword, a Ruby syntax error, and exit 0 with a Gemfile
/// every `bundle` command failed to parse. The exact pin supersedes it, so
/// it is dropped like a quoted constraint (`require: false` survives). The
/// real bundler must parse the rewritten Gemfile, install it frozen and load
/// rack from the vendored path; revert restores the original bytes.
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_drops_positional_constraints() {
    for gemfile in [
        "source \"https://rubygems.org\"\n\nRV = [\"~> 3.1\"]\ngem \"rack\", *RV\n",
        "source \"https://rubygems.org\"\n\ngem \"rack\", ENV.fetch(\"SOCKET_E2E_RV\", \"~> 3.1\")\n",
        "source \"https://rubygems.org\"\n\nRACK_VERSION = \"~> 3.1\"\ngem \"rack\", RACK_VERSION, require: false\n",
    ] {
        let Some((_tmp, proj, _bundler, purl)) = staged_rack_project("positional args") else {
            return;
        };
        std::fs::write(proj.join("Gemfile"), gemfile).unwrap();
        let relock = bundle(&proj, &["install"], false);
        assert!(
            relock.status.success(),
            "{gemfile:?} installs before vendor (test premise):\n{}",
            String::from_utf8_lossy(&relock.stderr)
        );
        let lock_before = std::fs::read(proj.join("Gemfile.lock")).unwrap();

        let (code, stdout, stderr) = run_socket(
            &proj,
            &[
                "vendor",
                "--json",
                "--offline",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        );
        assert_eq!(
            code, 0,
            "{gemfile:?}: vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        let env = parse_json_envelope(&stdout);
        assert_eq!(env["summary"]["applied"], 1, "{gemfile:?}: {env}");
        let wired = std::fs::read_to_string(proj.join("Gemfile")).unwrap();

        let install = bundle(&proj, &["install"], true);
        assert!(
            install.status.success(),
            "{gemfile:?}: frozen install of the rewritten Gemfile failed:\n{wired}\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        let probe = bundle(
            &proj,
            &[
                "exec",
                "ruby",
                "-e",
                "print Gem.loaded_specs.fetch(\"rack\").full_gem_path",
            ],
            true,
        );
        let loaded = String::from_utf8_lossy(&probe.stdout);
        assert!(
            probe.status.success() && loaded.contains(".socket/vendor/gem/"),
            "{gemfile:?}: rack must load from the vendored path ({purl}), got {loaded:?}:\n{}",
            String::from_utf8_lossy(&probe.stderr)
        );

        let (code, stdout, stderr) = run_socket(
            &proj,
            &[
                "vendor",
                "--revert",
                "--json",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        );
        assert_eq!(
            code, 0,
            "{gemfile:?}: revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert_eq!(
            std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
            gemfile,
            "revert restores the Gemfile byte-identical"
        );
        assert_eq!(
            std::fs::read(proj.join("Gemfile.lock")).unwrap(),
            lock_before,
            "revert restores Gemfile.lock byte-identical"
        );
    }
}

/// #1821: vendoring over a CRLF Gemfile keeps every line CRLF (the rewired
/// `gem` line used to end in a bare LF), a real frozen install accepts the
/// result, and revert restores the Gemfile byte for byte.
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_keeps_a_crlf_gemfile_crlf() {
    for gemfile in [
        "source \"https://rubygems.org\"\r\n\r\ngem \"rack\", \"~> 3.1\"\r\n",
        "source \"https://rubygems.org\"\r\n\r\ngem \"rack\", \"~> 3.1\", require: false # pinned\r\n",
    ] {
        let Some((_tmp, proj, _bundler, _purl)) = staged_rack_project("crlf gemfile") else {
            return;
        };
        std::fs::write(proj.join("Gemfile"), gemfile).unwrap();
        let relock = bundle(&proj, &["install"], false);
        assert!(
            relock.status.success(),
            "{gemfile:?} installs before vendor (test premise):\n{}",
            String::from_utf8_lossy(&relock.stderr)
        );
        let lock_before = std::fs::read(proj.join("Gemfile.lock")).unwrap();

        let (code, stdout, stderr) = run_socket(
            &proj,
            &[
                "vendor",
                "--json",
                "--offline",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        );
        assert_eq!(
            code, 0,
            "{gemfile:?}: vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        let env = parse_json_envelope(&stdout);
        assert_eq!(env["summary"]["applied"], 1, "{gemfile:?}: {env}");
        let wired = std::fs::read_to_string(proj.join("Gemfile")).unwrap();
        assert!(
            wired.contains(".socket/vendor/gem/")
                && wired.matches("\r\n").count() == wired.matches('\n').count()
                && wired.matches("\r\n").count() == wired.matches('\r').count(),
            "{gemfile:?}: the vendored Gemfile must stay CRLF throughout: {wired:?}"
        );

        let install = bundle(&proj, &["install"], true);
        assert!(
            install.status.success(),
            "{gemfile:?}: frozen install of the rewritten Gemfile failed:\n{wired}\n{}",
            String::from_utf8_lossy(&install.stderr)
        );

        let (code, stdout, stderr) = run_socket(
            &proj,
            &[
                "vendor",
                "--revert",
                "--json",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        );
        assert_eq!(
            code, 0,
            "{gemfile:?}: revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert_eq!(
            std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
            gemfile,
            "revert restores the Gemfile byte-identical"
        );
        assert_eq!(
            std::fs::read(proj.join("Gemfile.lock")).unwrap(),
            lock_before,
            "revert restores Gemfile.lock byte-identical"
        );
    }
}

/// The gem library a #985 project builds: its gemspec declares rack as a
/// development dependency. Writes `Gemfile` (the given body), the gemspec
/// and its lib, then installs unfrozen.
fn gemspec_library(proj: &Path, gemfile: &str) {
    std::fs::write(proj.join("Gemfile"), gemfile).unwrap();
    std::fs::create_dir_all(proj.join("lib")).unwrap();
    std::fs::write(proj.join("lib/mylib.rb"), "module Mylib; end\n").unwrap();
    std::fs::write(
        proj.join("mylib.gemspec"),
        "Gem::Specification.new do |s|\n  s.name = \"mylib\"\n  s.version = \"0.1.0\"\n  \
         s.summary = \"x\"\n  s.authors = [\"x\"]\n  s.files = [\"lib/mylib.rb\"]\n  \
         s.add_development_dependency \"rack\", \">= 3\"\nend\n",
    )
    .unwrap();
    let relock = bundle(proj, &["install"], false);
    assert!(
        relock.status.success(),
        "the gem library installs before vendor (test premise):\n{}\n{}",
        String::from_utf8_lossy(&relock.stdout),
        String::from_utf8_lossy(&relock.stderr)
    );
}

/// #985: a gem library whose Gemfile's `gemspec` directive declares rack as
/// a development dependency, and whose Gemfile declares rack AFTER the
/// directive. Bundler 2.7+ merges the two requirements, and for a path gem
/// it then rejects even the lock it writes itself under frozen mode, so
/// vendoring refuses before any write (before the fix it wrote a pair whose
/// frozen install exited 16) and names the remedy. With the `gem` line moved
/// above `gemspec`, the vendored pair installs frozen and reverts cleanly.
/// Bundler < 2.7 never merges and vendors either order.
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_gemspec_dev_dependency_refuses_or_installs_frozen() {
    let Some((_tmp, proj, bundler, purl)) = staged_rack_project("gemspec dev dependency") else {
        return;
    };
    let after = "source \"https://rubygems.org\"\n\ngemspec\n\ngem \"rack\", \"~> 3.1\"\n";
    let before = "source \"https://rubygems.org\"\n\ngem \"rack\", \"~> 3.1\"\n\ngemspec\n";
    let vendor = |proj: &Path| {
        run_socket(
            proj,
            &[
                "vendor",
                "--json",
                "--offline",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        )
    };

    if bundler.at_least(2, 7) {
        gemspec_library(&proj, after);
        let lock_before = std::fs::read(proj.join("Gemfile.lock")).unwrap();
        let (code, stdout, stderr) = vendor(&proj);
        assert_ne!(
            code, 0,
            "vendor must refuse.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        let env = parse_json_envelope(&stdout);
        assert_eq!(env["summary"]["applied"], 0, "nothing vendored: {env}");
        let event = env["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["purl"] == purl)
            .unwrap_or_else(|| panic!("an event for {purl}: {env}"));
        assert_eq!(
            event["errorCode"], "gemfile_declaration_not_editable",
            "event: {event}"
        );
        assert!(
            event["error"]
                .as_str()
                .is_some_and(|e| e.contains("above `gemspec`")),
            "the refusal names the remedy: {event}"
        );
        assert_eq!(
            std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
            after
        );
        assert_eq!(
            std::fs::read(proj.join("Gemfile.lock")).unwrap(),
            lock_before
        );
        assert!(
            !proj.join(".socket/vendor/gem").exists(),
            "no vendored copy is written"
        );
    }

    // The remedy (and, on bundler < 2.7, either order): vendored, frozen.
    let gemfile = if bundler.at_least(2, 7) {
        before
    } else {
        after
    };
    gemspec_library(&proj, gemfile);
    let lock_before = std::fs::read(proj.join("Gemfile.lock")).unwrap();
    let (code, stdout, stderr) = vendor(&proj);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let wired = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
    let version = purl.rsplit('@').next().unwrap();
    assert!(
        wired.contains(&format!("  rack (= {version})!\n")),
        "exact pin:\n{wired}"
    );
    let install = bundle(&proj, &["install"], true);
    assert!(
        install.status.success(),
        "frozen install of the vendored pair failed:\n{wired}\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
        wired,
        "the frozen install keeps the lock byte-identical"
    );
    let probe = bundle(
        &proj,
        &[
            "exec",
            "ruby",
            "-e",
            "print Gem.loaded_specs.fetch(\"rack\").full_gem_path",
        ],
        true,
    );
    let loaded = String::from_utf8_lossy(&probe.stdout);
    assert!(
        probe.status.success() && loaded.contains(".socket/vendor/gem/"),
        "rack must load from the vendored path ({purl}), got {loaded:?}:\n{}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
        gemfile,
        "revert restores the Gemfile byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        lock_before,
        "revert restores Gemfile.lock byte-identical"
    );
}

/// #2151: a gem only the gemspec declares (a development dependency of a
/// gem library) is refused, and both ways out the refusal names work when
/// followed. Hosted mode's warning used to send the user here, where the
/// refusal named no way out at all. With the literal `gem` line above
/// `gemspec` the gem vendors and installs frozen; with the Gemfile left as
/// it was, agent mode patches the installed gem.
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_gemspec_only_dependency_refusal_names_remedies_that_work() {
    let Some((_tmp, proj, _bundler, purl)) = staged_rack_project("gemspec-only dependency") else {
        return;
    };
    let version = purl.rsplit('@').next().unwrap();
    let hidden = "source \"https://rubygems.org\"\n\ngemspec\n";
    let cwd = proj.to_str().unwrap();
    let vendor = |proj: &Path| run_socket(proj, &["vendor", "--json", "--offline", "--cwd", cwd]);
    let locked = |proj: &Path| {
        let lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
        locked_gem_version(&lock, DEP)
    };

    let bundle_config = proj.join(".bundle/config");
    let committed_config = std::fs::read(&bundle_config).unwrap();
    gemspec_library(&proj, hidden);
    assert_eq!(locked(&proj).as_deref(), Some(version), "test premise");
    let lock_before = std::fs::read(proj.join("Gemfile.lock")).unwrap();
    let (code, stdout, stderr) = vendor(&proj);
    assert_ne!(
        code, 0,
        "vendor must refuse.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    let event = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["purl"] == purl)
        .unwrap_or_else(|| panic!("an event for {purl}: {env}"));
    assert_eq!(
        event["errorCode"], "gemfile_declaration_not_editable",
        "event: {event}"
    );
    let error = event["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("one literal `gem \"rack\"` line above `gemspec`")
            && error.contains("`--mode agent`"),
        "the refusal names its ways out: {event}"
    );
    assert!(
        !error.contains("--mode hosted"),
        "hosted mode refuses this gem for the same reason: {event}"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
        hidden
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        lock_before
    );
    assert!(
        !proj.join(".socket/vendor/gem").exists(),
        "no vendored copy is written"
    );

    // The first way out: one literal `gem` line above `gemspec`.
    let declared = "source \"https://rubygems.org\"\n\ngem \"rack\"\n\ngemspec\n";
    gemspec_library(&proj, declared);
    assert_eq!(locked(&proj).as_deref(), Some(version), "test premise");
    let lock_declared = std::fs::read(proj.join("Gemfile.lock")).unwrap();
    let (code, stdout, stderr) = vendor(&proj);
    assert_eq!(
        code, 0,
        "vendor failed with the remedy followed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let wired = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
    let install = bundle(&proj, &["install"], true);
    assert!(
        install.status.success(),
        "frozen install of the vendored pair failed:\n{wired}\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
        wired,
        "the frozen install keeps the lock byte-identical"
    );
    let gem_path = |proj: &Path| {
        let probe = bundle(
            proj,
            &[
                "exec",
                "ruby",
                "-e",
                "print Gem.loaded_specs.fetch(\"rack\").full_gem_path",
            ],
            true,
        );
        assert!(
            probe.status.success(),
            "rack must load:\n{}",
            String::from_utf8_lossy(&probe.stderr)
        );
        String::from_utf8_lossy(&probe.stdout).into_owned()
    };
    let loaded = gem_path(&proj);
    assert!(
        loaded.contains(".socket/vendor/gem/"),
        "rack must load from the vendored path ({purl}), got {loaded:?}"
    );
    let (code, stdout, stderr) = run_socket(&proj, &["vendor", "--revert", "--json", "--cwd", cwd]);
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
        declared,
        "revert restores the Gemfile byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        lock_declared,
        "revert restores Gemfile.lock byte-identical"
    );

    // The second way out: agent mode, with the Gemfile as it was. Bundler
    // <= 2.0 persisted `BUNDLE_FROZEN: "true"` into `.bundle/config` on the
    // frozen install above and would refuse the changed Gemfile; a
    // developer's unfrozen install runs from the committed config.
    std::fs::write(&bundle_config, &committed_config).unwrap();
    gemspec_library(&proj, hidden);
    assert_eq!(locked(&proj).as_deref(), Some(version), "test premise");
    let installed_rb = PathBuf::from(gem_path(&proj)).join("lib/rack.rb");
    let marker = "SOCKET-PATCH-VENDOR-E2E-MARKER";
    assert!(
        !std::fs::read_to_string(&installed_rb)
            .unwrap()
            .contains(marker),
        "the installed gem starts unpatched (test premise)"
    );
    let (code, stdout, stderr) = run_socket(&proj, &["apply", "--json", "--offline", "--cwd", cwd]);
    assert_eq!(
        code, 0,
        "agent mode failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        std::fs::read_to_string(&installed_rb)
            .unwrap()
            .contains(marker),
        "agent mode patches the installed gem"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
        hidden,
        "agent mode leaves the Gemfile alone"
    );
}

/// #1808: a CRLF `Gemfile.lock` (a Git for Windows `autocrlf` checkout, or
/// `eol=crlf`; bundler keeps CRLF on purpose) vendors like an LF one. The
/// dry run and the wet run both succeed, the wired lock keeps CRLF on every
/// line, a frozen fresh-checkout install accepts it byte-stably, a re-run
/// is byte-stable, and `--revert` hands back the CRLF lock byte for byte.
#[test]
#[ignore = "host capstone: shells out to a real bundler >= 1.17; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_crlf_lock_fresh_checkout_and_revert() {
    let Some((tmp, proj, _bundler, _purl)) = staged_rack_project("crlf lock") else {
        return;
    };
    let lock_path = proj.join("Gemfile.lock");
    let gemfile_path = proj.join("Gemfile");
    let lf = std::fs::read_to_string(&lock_path).unwrap();
    let crlf = lf.replace('\n', "\r\n");
    std::fs::write(&lock_path, &crlf).unwrap();
    let gemfile_before = std::fs::read(&gemfile_path).unwrap();
    // Some bundlers (4.0.21) refuse a frozen install of any CRLF lock, even
    // one socket-patch never touched; the frozen leg below then has nothing
    // to compare against.
    let pristine = tmp.path().join("pristine");
    std::fs::create_dir_all(&pristine).unwrap();
    std::fs::copy(&gemfile_path, pristine.join("Gemfile")).unwrap();
    std::fs::copy(&lock_path, pristine.join("Gemfile.lock")).unwrap();
    common::fs_tree::copy_tree(&proj.join(".bundle"), &pristine.join(".bundle"));
    let frozen_crlf_ok = bundle(&pristine, &["install"], true).status.success();
    let cwd = proj.to_str().unwrap();
    let vendor = |extra: &[&str]| {
        let mut args = vec!["vendor", "--json", "--offline", "--cwd", cwd];
        args.extend_from_slice(extra);
        run_socket(&proj, &args)
    };

    let (code, stdout, stderr) = vendor(&["--dry-run"]);
    assert_eq!(code, 0, "dry run:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(!stdout.contains("apply_failed"), "dry run:\n{stdout}");
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        crlf,
        "a dry run writes nothing"
    );

    let (code, stdout, stderr) = vendor(&[]);
    assert_eq!(code, 0, "vendor:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let wired = std::fs::read_to_string(&lock_path).unwrap();
    assert_eq!(
        wired.matches('\n').count(),
        wired.matches("\r\n").count(),
        "every line of the wired lock keeps CRLF:\n{wired:?}"
    );
    let copy_rel = format!(".socket/vendor/gem/{UUID}/");
    assert!(
        wired.starts_with(&format!("PATH\r\n  remote: {copy_rel}")),
        "the PATH section is spliced in CRLF:\n{wired:?}"
    );
    assert!(
        wired.contains(&format!("\r\n  {DEP} (= ")),
        "the DEPENDENCIES pin is spliced in CRLF:\n{wired:?}"
    );

    // Bundler reads the CRLF pair as wired and keeps it byte-identical.
    let fresh = tmp.path().join("fresh");
    if !frozen_crlf_ok {
        println!(
            "SKIP frozen leg of e2e_vendor_gem_build (crlf lock): this bundler refuses a \
             frozen install of the pristine CRLF lock too"
        );
    }
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&gemfile_path, fresh.join("Gemfile")).unwrap();
    std::fs::copy(&lock_path, fresh.join("Gemfile.lock")).unwrap();
    common::fs_tree::copy_tree(&proj.join(".socket"), &fresh.join(".socket"));
    common::fs_tree::copy_tree(&proj.join(".bundle"), &fresh.join(".bundle"));
    let ci = bundle(&fresh, &["install"], frozen_crlf_ok);
    assert!(
        ci.status.success(),
        "install of the CRLF pair (frozen: {frozen_crlf_ok}):\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    assert_eq!(
        std::fs::read_to_string(fresh.join("Gemfile.lock")).unwrap(),
        wired,
        "bundler accepts the wired CRLF lock as is"
    );

    let (code, stdout, stderr) = vendor(&[]);
    assert_eq!(code, 0, "re-run:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        wired,
        "a re-run takes the in-sync path and leaves the lock alone"
    );

    let (code, stdout, stderr) = run_socket(&proj, &["vendor", "--revert", "--json", "--cwd", cwd]);
    assert_eq!(code, 0, "revert:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        !stdout.contains("drifted"),
        "a clean revert reports no drift:\n{stdout}"
    );
    assert_eq!(std::fs::read(&gemfile_path).unwrap(), gemfile_before);
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        crlf,
        "revert restores the CRLF lock byte for byte"
    );
}

// ── a gem locked as precompiled platform gems ──────────────────────────

/// The fixture gem of the platform-gem capstone: published as platform
/// gems only, with a pure-Ruby dependency.
const PLAT: &str = "sockplat";
const PLAT_VERSION: &str = "1.0.0";
const PLAT_PRISTINE: &str = "module Sockplat\n  VERSION = \"1.0.0\"\nend\n";

/// Builds, with RubyGems itself, in the current directory:
///
/// * `repo/`: a static `file://` rubygems source (see
///   [`private_gem_source`]) serving `sockplat 1.0.0` as PLATFORM gems
///   only — one for this machine's platform and two foreign ones — its
///   dependency `sockdep 1.0.0`, and `sockparent 1.0.0`, which depends on
///   it. A platform gem needs no binary: a pure-Ruby gem whose gemspec
///   sets `platform` is one.
/// * `service/`: what the patch service serves for the patch of
///   `sockplat` — the patched ruby gem, the patched platform gem of each
///   platform and the stub gemspec of each
///   (`Gem::Specification#to_ruby`).
/// * `platforms`: the platforms, this machine's first.
///
/// `pristine.rb` / `patched.rb` (the caller's) are `lib/sockplat.rb`
/// before and after the patch. Beside it every gem carries
/// `lib/<name>/build`, which names the build it is: the one file that
/// tells one platform's gem from another's.
const PLATFORM_GEMS_RB: &str = r##"
require "rubygems/package"
require "zlib"
require "fileutils"

out = Dir.pwd
local = Gem::Platform.local
own = Gem::Platform.new([local.cpu, local.os, nil]).to_s
platforms = ([own] + %w[x86_64-linux arm64-darwin x64-mingw-ucrt]).uniq.first(3)
bodies = { "upstream" => File.read("pristine.rb"), "patched" => File.read("patched.rb") }

build = lambda do |dir, name, platform, body, deps|
  work = File.join(out, dir, "#{name}-#{platform || "ruby"}")
  FileUtils.mkdir_p(File.join(work, "lib", name))
  File.write(File.join(work, "lib/#{name}.rb"), body)
  File.write(File.join(work, "lib/#{name}/build"), platform || "ruby")
  spec = Gem::Specification.new do |s|
    s.name = name
    s.version = "1.0.0"
    s.platform = platform if platform
    s.summary = "fixture"
    s.authors = ["fixture"]
    s.files = ["lib/#{name}.rb", "lib/#{name}/build"]
    deps.each { |dep| s.add_runtime_dependency(dep, ">= 1.0") }
  end
  [spec, Dir.chdir(work) { File.join(work, Gem::Package.build(spec)) }]
end

FileUtils.mkdir_p(["repo/gems", "repo/quick/Marshal.4.8", "service"])
tuples = []
publish = lambda do |spec, file|
  FileUtils.cp(file, "repo/gems")
  tuples << [spec.name, spec.version, spec.platform.to_s]
  File.binwrite("repo/quick/Marshal.4.8/#{spec.full_name}.gemspec.rz",
                Zlib::Deflate.deflate(Marshal.dump(spec)))
end
publish.call(*build.call("upstream", "sockdep", nil, "module Sockdep; end\n", []))
publish.call(*build.call("upstream", "sockparent", nil, "require \"sockplat\"\n", ["sockplat"]))
platforms.each do |platform|
  publish.call(*build.call("upstream", "sockplat", platform, bodies["upstream"], ["sockdep"]))
end
{ "specs.4.8.gz" => tuples, "latest_specs.4.8.gz" => tuples, "prerelease_specs.4.8.gz" => [] }.each do |f, v|
  Zlib::GzipWriter.open("repo/#{f}") { |gz| gz.write(Marshal.dump(v)) }
end
([nil] + platforms).each do |platform|
  spec, file = build.call("patched", "sockplat", platform, bodies["patched"], ["sockdep"])
  FileUtils.cp(file, "service")
  File.write("service/#{spec.full_name}.gemspec", spec.to_ruby)
end
File.write("platforms", platforms.join("\n"))
"##;

/// The `sha512-<base64>` SRI string of `bytes`.
fn sri(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha512};
    format!("sha512-{}", b64(&Sha512::digest(bytes)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// The uuid of the patch of `platform`'s patched build, for the gem patch
/// `uuid`: each patched platform gem has a patch of its own.
fn build_uuid(uuid: &str, platform: &str) -> String {
    let hex = sha256_hex(format!("{uuid}/{platform}").as_bytes());
    format!(
        "{}-{}-4{}-8{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..32]
    )
}

/// The purl of the fixture gem's platform gem of `platform`.
fn platform_purl(platform: &str) -> String {
    format!("pkg:gem/{PLAT}@{PLAT_VERSION}?platform={platform}")
}

/// A patch service answering for the gem patch `uuid` the way the wire
/// contract has it. The gem's fix is that one patch, the ruby gem's
/// (`purl`). Its reference serves the ruby gem (`tarball`) with its stub
/// and, for a request that asks (`"gemBuilds": true`), names its registry
/// under a snapshot URL and lists every gem of the version
/// (`registryOverride.identifiers.gemBuilds`): the ruby gem, each platform
/// of `patched` with the patch of its patched build ([`build_uuid`]), and
/// each of `upstream` with none (the registry hands on upstream's own gem
/// for it). Each of those patches serves that platform's gem (`tarball`)
/// and stub gemspec, and one request answers for every uuid it names. The
/// URLs name the production host, so the run reaches them only through
/// `--patch-server-url`.
async fn platform_patch_service(
    fixture: &Path,
    purl: &str,
    uuid: &str,
    patched: &[String],
    upstream: &[String],
) -> MockServer {
    let server = MockServer::start().await;
    let leaf = format!("{PLAT}-{PLAT_VERSION}");
    let file_of = |platform: Option<&str>| match platform {
        Some(platform) => format!("{leaf}-{platform}"),
        None => leaf.clone(),
    };
    let read = |dir: &str, file: String| std::fs::read(fixture.join(dir).join(file)).unwrap();
    // The artifacts of the patch `own` of the gem of `platform`, each
    // mounted where its URL says.
    let mut mounts = Vec::new();
    let mut artifacts = |own: &str, platform: Option<&str>| {
        let mut out = Vec::new();
        for (kind, ext) in [("tarball", "gem"), ("gem-stub-gemspec", "gemspec")] {
            let bytes = read("service", format!("{}.{ext}", file_of(platform)));
            let route = format!(
                "/patch/gem/{PLAT}/{PLAT_VERSION}/grant-token/{own}/{}.{ext}",
                file_of(platform)
            );
            out.push(serde_json::json!({
                "kind": kind,
                "url": format!("https://patch.socket.dev{route}"),
                "contentType": "application/octet-stream",
                "sizeBytes": bytes.len(),
                "integrity": { "sha512": sri(&bytes) },
            }));
            mounts.push((route, bytes));
        }
        serde_json::Value::Array(out)
    };

    let ruby_sha = sha256_hex(&read("service", format!("{leaf}.gem")));
    let mut builds = vec![serde_json::json!({
        "platform": "ruby", "gemChecksumSha256": ruby_sha, "patchUuid": uuid,
    })];
    let mut references = serde_json::Map::new();
    for platform in patched {
        let own = build_uuid(uuid, platform);
        let gem = read("service", format!("{}.gem", file_of(Some(platform))));
        builds.push(serde_json::json!({
            "platform": platform, "gemChecksumSha256": sha256_hex(&gem), "patchUuid": own,
        }));
        let artifacts = artifacts(&own, Some(platform));
        references.insert(
            own,
            serde_json::json!({
                "status": "granted",
                "purl": platform_purl(platform),
                "url": artifacts[0]["url"],
                "artifacts": artifacts,
            }),
        );
    }
    for platform in upstream {
        let gem = read("repo/gems", format!("{}.gem", file_of(Some(platform))));
        builds.push(serde_json::json!({
            "platform": platform, "gemChecksumSha256": sha256_hex(&gem), "patchUuid": null,
        }));
    }
    builds.sort_by_key(|build| build["platform"].as_str().map(str::to_string));
    let key = &sha256_hex(
        serde_json::Value::from(builds.clone())
            .to_string()
            .as_bytes(),
    )[..12];
    let registry = format!("https://patch.socket.dev/patch-registry/gem/grant-token/{uuid}/");
    let artifacts = artifacts(uuid, None);
    let reference = |listed: bool| {
        let mut identifiers = serde_json::json!({
            "name": PLAT, "version": PLAT_VERSION, "gemChecksumSha256": ruby_sha,
        });
        let mut index_url = registry.clone();
        if listed {
            identifiers["gemBuilds"] = builds.clone().into();
            index_url = format!("{registry}s/{key}");
        }
        serde_json::json!({
            "status": "granted",
            "purl": purl,
            "url": artifacts[0]["url"],
            "artifacts": artifacts,
            "registryOverride": {
                "kind": "rubygems-compact-index",
                "indexUrl": index_url,
                "identifiers": identifiers,
            },
        })
    };
    let (with_list, plain) = (reference(true), reference(false));
    let gem_patch = uuid.to_string();
    Mock::given(method("POST"))
        .and(path_regex(r"/(patch|patches)/package$"))
        .respond_with(move |request: &wiremock::Request| {
            let asked: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or_default();
            let mut results = serde_json::Map::new();
            for asked_uuid in asked["uuids"].as_array().into_iter().flatten() {
                let Some(asked_uuid) = asked_uuid.as_str() else {
                    continue;
                };
                let reference = match asked_uuid == gem_patch {
                    true if asked["gemBuilds"] == true => Some(&with_list),
                    true => Some(&plain),
                    false => references.get(asked_uuid),
                };
                if let Some(reference) = reference {
                    results.insert(asked_uuid.to_string(), reference.clone());
                }
            }
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
        })
        .mount(&server)
        .await;
    for (route, bytes) in mounts {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(&server)
            .await;
    }
    server
}

/// A second patch of the fixture gem, published after [`UUID`].
const UUID_NEXT: &str = "4d5e6f7a-8b9c-4b2c-9d3e-123456789abc";

/// The artifacts `server` has been asked to serve, by file name.
async fn artifact_downloads(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().starts_with("/patch/gem/"))
        .filter_map(|r| r.url.path().rsplit('/').next().map(str::to_string))
        .collect()
}

/// How many grants and artifact downloads `server` has answered.
async fn service_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with("/package") || r.url.path().starts_with("/patch/gem/"))
        .count()
}

/// The uuids each package reference request to `server` named, in arrival
/// order, each list sorted. Every request must have asked for the list of
/// the gem's builds.
async fn reference_requests(server: &MockServer) -> Vec<Vec<String>> {
    let requests = server.received_requests().await.unwrap_or_default();
    let mut asked = Vec::new();
    for request in requests
        .iter()
        .filter(|request| request.url.path().ends_with("/package"))
    {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        assert_eq!(
            body["gemBuilds"], true,
            "every package reference request asks for the list of the gem's builds: {body}"
        );
        let uuids = body["uuids"].as_array().into_iter().flatten();
        let mut uuids: Vec<String> = uuids
            .filter_map(|uuid| uuid.as_str().map(str::to_string))
            .collect();
        uuids.sort();
        asked.push(uuids);
    }
    asked
}

/// The events of `env` with `action` that are a platform gem's
/// (`details.gemFix`), as `(purl, uuid, gemFix, platform, errorCode)`, in
/// envelope order.
fn platform_gem_events(
    env: &serde_json::Value,
    action: &str,
) -> Vec<(String, String, String, String, String)> {
    let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_string();
    let events = env["events"].as_array().into_iter().flatten();
    events
        .filter(|event| event["action"] == action && event["details"]["gemFix"].is_string())
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

/// One event per platform gem of `platforms` (in lock order), each under
/// that platform's own patch and naming the gem's patch as its fix.
fn per_platform_gem(
    platforms: &[String],
    code: &str,
) -> Vec<(String, String, String, String, String)> {
    platforms
        .iter()
        .map(|platform| {
            (
                platform_purl(platform),
                build_uuid(UUID, platform),
                UUID.to_string(),
                platform.clone(),
                code.to_string(),
            )
        })
        .collect()
}

/// A gem bundler locks as PRECOMPILED PLATFORM gems (the shape of
/// nokogiri: one lock entry per platform, no plain `name (version)`), which
/// cannot be vendored as its own tree because bundler never builds a
/// `path:` gem's extensions. Vendor takes the patched platform gem of
/// EVERY locked platform instead, each from that platform's own patch:
///
///   1. the REAL bundler resolves the fixture gem from a local source that
///      publishes it as platform gems only, and locks this machine's
///      platform and two foreign ones;
///   2. while one locked platform has no patched build (the service lists
///      upstream's own gem for it) the gem is not vendored: the run exits
///      0, says so in ONE line that names the platform, asks for the gem
///      patch's reference alone, downloads no gem and writes nothing;
///   3. with a patched build of every platform, `vendor` asks for the gem
///      patch's reference and then for the platform patches in ONE
///      request, unpacks one tree per platform from that platform's own
///      gem (each with its stub gemspec), moves every platform block into
///      one `PATH` section, wires the Gemfile, records each tree's patch
///      and digests in the ledger, and reports one event per platform gem;
///   4. `vex` attests each platform gem `(vendored)` under its own patch,
///      and `vendor --check` covers every platform's tree (a tampered
///      FOREIGN tree fails it);
///   5. a fresh checkout — the committable files only, and no request to
///      the patch service — installs frozen with a byte-stable lock, loads
///      the PATCHED file from the tree of the running platform, and an
///      unfrozen install and `bundle lock` regenerate the same lock;
///   6. a second `vendor` run changes nothing and asks the service nothing,
///      and a newer patch that lacks one platform's patched build leaves
///      the vendored one in force;
///   7. a ledger entry that names the platforms of its copy and no patch
///      for their trees (`gemPlatforms`, as a development build recorded
///      it) still checks and reverts, and the next `vendor` run records the
///      patch of each tree in its place;
///   8. `vendor --revert` restores the Gemfile and the lock byte for byte
///      (the registry CHECKSUMS tokens included) and removes the trees.
///
/// Run for a gem the Gemfile declares, and for one it only reaches through
/// another gem (wired by the managed block).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real bundler >= 2.3; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
async fn gem_vendor_platform_gems_fresh_checkout_bundle_install_and_revert() {
    // Floor 2.3: the oldest bundler this layout was run against (it locks
    // one entry per platform and reads a path source's per-platform
    // gemspecs the same way up to 4.x).
    let Some(bundler) = bundler_e2e::gate("e2e_vendor_gem_build", "platform gems", (2, 3), &|c| {
        cache_env::isolate(c);
    }) else {
        return;
    };
    for declared in ["sockplat", "sockparent"] {
        platform_gems_capstone(&bundler, declared).await;
    }
}

/// The platform-gem capstone for a project whose Gemfile declares
/// `declared`: the platform gem itself, or `sockparent`, which makes the
/// platform gem a transitive dependency.
async fn platform_gems_capstone(bundler: &bundler_e2e::Bundler, declared: &str) {
    let tmp = tempfile::tempdir().unwrap();
    // Bundler spells the lock's `file://` remote with the real path.
    let base = tmp.path().canonicalize().unwrap();

    // 1. The fixture source and service artifacts.
    let marker = format!("module Sockplat\n  SOCKET_PATCH_VENDOR_E2E = \"{UUID}\"\nend\n");
    let patched = format!("{PLAT_PRISTINE}{marker}");
    let fixture = base.join("fixture");
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::write(fixture.join("pristine.rb"), PLAT_PRISTINE).unwrap();
    std::fs::write(fixture.join("patched.rb"), &patched).unwrap();
    let mut ruby = Command::new("ruby");
    ruby.args(["-e", PLATFORM_GEMS_RB]).current_dir(&fixture);
    cache_env::isolate(&mut ruby);
    let built = ruby.output().expect("failed to run ruby");
    assert!(
        built.status.success(),
        "building the platform gem fixture failed:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let platforms: Vec<String> = std::fs::read_to_string(fixture.join("platforms"))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let (own, foreign) = platforms.split_first().expect("platforms");
    assert_eq!(foreign.len(), 2, "two foreign platforms: {platforms:?}");

    let proj = base.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        format!(
            "source \"file://{}\"\n\ngem \"{declared}\"\n",
            fixture.join("repo").display()
        ),
    )
    .unwrap();
    let config = bundle(
        &proj,
        &argv(&bundler.config_local_args("path", "vendor/bundle")),
        false,
    );
    assert!(config.status.success(), "bundle config failed");
    let install = bundle(&proj, &["install"], false);
    assert!(
        install.status.success(),
        "fixture `bundle install` failed:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    for platform in &platforms {
        let add = bundle(&proj, &["lock", "--add-platform", platform.as_str()], false);
        assert!(
            add.status.success(),
            "`bundle lock --add-platform {platform}` failed:\n{}",
            String::from_utf8_lossy(&add.stderr)
        );
    }
    let lock_path = proj.join("Gemfile.lock");
    let gemfile_path = proj.join("Gemfile");
    let lock_before = std::fs::read(&lock_path).unwrap();
    let gemfile_before = std::fs::read(&gemfile_path).unwrap();
    let lock_text = String::from_utf8(lock_before.clone()).unwrap();
    // The premise: bundler locked one entry per platform, each with its
    // dependency line, and no plain `sockplat (1.0.0)`. Bundler sorts a
    // section's specs by full name.
    let mut sorted = platforms.clone();
    sorted.sort();
    let blocks: String = sorted
        .iter()
        .map(|p| format!("    {PLAT} ({PLAT_VERSION}-{p})\n      sockdep (>= 1.0)\n"))
        .collect();
    assert!(
        lock_text.contains(&blocks)
            && !lock_text.contains(&format!("    {PLAT} ({PLAT_VERSION})\n")),
        "bundler must lock {PLAT} as platform gems only (test premise):\n{lock_text}"
    );

    let mut ruby = Command::new("ruby");
    ruby.args(["-e", "puts Gem.ruby_api_version"]);
    cache_env::isolate(&mut ruby);
    let api = ruby.output().expect("failed to run ruby");
    let api = String::from_utf8_lossy(&api.stdout).trim().to_string();
    let installed_rb = proj
        .join("vendor/bundle/ruby")
        .join(&api)
        .join("gems")
        .join(format!("{PLAT}-{PLAT_VERSION}-{own}"))
        .join("lib/sockplat.rb");
    assert_eq!(
        std::fs::read_to_string(&installed_rb).expect("the installed platform gem"),
        PLAT_PRISTINE,
        "bundler installs this machine's platform gem into a platform-suffixed dir"
    );

    // The patch record is the ruby gem's, as the patch service publishes it.
    let purl = format!("pkg:gem/{PLAT}@{PLAT_VERSION}?platform=ruby");
    stage_patch_with_vuln(
        &proj,
        &purl,
        "lib/sockplat.rb",
        PLAT_PRISTINE.as_bytes(),
        patched.as_bytes(),
    );
    let vendor_in = |root: &Path, server: &MockServer, json: bool| {
        let uri = server.uri();
        let mut args = vec!["vendor"];
        if json {
            args.push("--json");
        }
        args.extend(["--cwd", root.to_str().unwrap(), "--patch-server-url", &uri]);
        run_socket(root, &args)
    };
    let vendor = |server: &MockServer| vendor_in(&proj, server, true);
    // The project as it is before anything is vendored, for a person's run.
    let unvendored = base.join("unvendored");
    common::fs_tree::copy_tree(&proj, &unvendored);

    // 2. One locked platform has no patched build yet: the gem is not
    //    vendored, in one line, the run does not fail, no gem is
    //    downloaded and nothing is written.
    let (with_build, without_build) = platforms.split_at(2);
    let partial = platform_patch_service(&fixture, &purl, UUID, with_build, without_build).await;
    let mut have = with_build.to_vec();
    have.sort();
    let not_vendored = format!(
        "{PLAT}@{PLAT_VERSION} is not vendored: no patched build yet for {} ({} and {} have \
         one). Vendored mode needs every locked platform; `scan --mode hosted` can patch the \
         others now.",
        without_build[0], have[0], have[1]
    );
    let (code, stdout, stderr) = vendor(&partial);
    assert_eq!(
        code, 0,
        "a platform with no patched build is no failure.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 0, "nothing vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "and nothing failed: {env}");
    assert_eq!(env["summary"]["skipped"], 1, "one counted skip: {env}");
    let skipped = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["errorCode"] == "vendor_prebuilt_platform_pending")
        .unwrap_or_else(|| panic!("a vendor_prebuilt_platform_pending event: {env}"));
    assert_eq!(skipped["action"], "skipped", "{skipped}");
    assert_eq!(skipped["reason"], not_vendored.as_str(), "{skipped}");
    assert_eq!(
        artifact_downloads(&partial).await,
        Vec::<String>::new(),
        "the package reference says what is built: nothing is downloaded"
    );
    assert_eq!(
        reference_requests(&partial).await,
        [[UUID]],
        "the reference of the gem's own patch, and nothing else"
    );
    assert_eq!(std::fs::read(&gemfile_path).unwrap(), gemfile_before);
    assert_eq!(std::fs::read(&lock_path).unwrap(), lock_before);
    assert!(!proj.join(".socket/vendor").exists(), "nothing is written");
    // For a person: that one line, and no warning. (The other line of
    // stderr is the note that this run names no API token.)
    let (code, stdout, stderr) = vendor_in(&unvendored, &partial, false);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let said: Vec<&str> = stderr
        .lines()
        .filter(|line| !line.contains("SOCKET_API_TOKEN"))
        .collect();
    assert_eq!(
        said,
        [not_vendored.as_str()],
        "one line on stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 skipped."),
        "{stdout}"
    );
    assert!(!unvendored.join(".socket/vendor").exists());
    drop(partial);

    // 3. A patched build of every platform: vendor.
    let server = platform_patch_service(&fixture, &purl, UUID, &platforms, &[]).await;
    let (code, stdout, stderr) = vendor(&server);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");
    assert_eq!(
        platform_gem_events(&env, "applied"),
        per_platform_gem(&sorted, ""),
        "one `applied` event per platform gem, each under its own patch: {env}"
    );
    assert_eq!(env["summary"]["applied"], 3, "each is counted: {env}");
    // The gem patch's reference, then ONE request for the platform patches.
    let mut own_patches: Vec<String> = platforms.iter().map(|p| build_uuid(UUID, p)).collect();
    own_patches.sort();
    assert_eq!(
        reference_requests(&server).await,
        [vec![UUID.to_string()], own_patches.clone()],
        "one batched reference request for the platform patches"
    );
    // The platform gems and their stubs are all that is downloaded: the
    // ruby gem the gem patch's reference names is not.
    let mut downloaded = artifact_downloads(&server).await;
    downloaded.sort();
    let mut platform_files: Vec<String> = platforms
        .iter()
        .flat_map(|p| ["gem", "gemspec"].map(|ext| format!("{PLAT}-{PLAT_VERSION}-{p}.{ext}")))
        .collect();
    platform_files.sort();
    assert_eq!(downloaded, platform_files);

    // One tree per platform, each that platform's own patched gem with its
    // own stub gemspec.
    let copy_rel = format!(".socket/vendor/gem/{UUID}/{PLAT}-{PLAT_VERSION}");
    for platform in &platforms {
        let tree = proj.join(&copy_rel).join(platform);
        assert_eq!(
            std::fs::read_to_string(tree.join("lib/sockplat.rb")).unwrap(),
            patched,
            "{platform}: the vendored tree must hold the patched bytes"
        );
        assert_eq!(
            &std::fs::read_to_string(tree.join("lib/sockplat/build")).unwrap(),
            platform,
            "{platform}: the tree is that platform's own gem"
        );
        let stub = std::fs::read_to_string(tree.join(format!("{PLAT}.gemspec")))
            .unwrap_or_else(|e| panic!("{platform}: stub gemspec not materialized: {e}"));
        assert!(
            stub.contains(&format!("s.platform = \"{platform}\"")),
            "{platform}: the stub is the platform gem's:\n{stub}"
        );
    }
    assert!(
        !proj
            .join(&copy_rel)
            .join(format!("{PLAT}.gemspec"))
            .exists(),
        "no ruby-platform gemspec at the vendored dir's root"
    );

    // The pair edit: `path:` on the declaration, every platform block in
    // one PATH section ahead of GEM, the `(= v)!` pin, bare CHECKSUMS.
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    assert!(
        gemfile.contains(&format!(
            "gem \"{PLAT}\", \"{PLAT_VERSION}\", path: \"{copy_rel}\""
        )),
        "Gemfile line not rewritten to the exact-pin + path: form:\n{gemfile}"
    );
    assert_eq!(
        gemfile.contains("# >>> socket-patch vendor (managed) >>>"),
        declared != PLAT,
        "only a gem the Gemfile did not declare is wired by the managed block:\n{gemfile}"
    );
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.starts_with(&format!(
            "PATH\n  remote: {copy_rel}\n  specs:\n{blocks}\nGEM\n"
        )),
        "every platform block must sit in one PATH section ahead of GEM:\n{lock}"
    );
    assert!(
        lock.contains(&format!("\n  {PLAT} (= {PLAT_VERSION})!\n")),
        "DEPENDENCIES pin missing:\n{lock}"
    );
    assert!(
        !lock.contains(&format!("\n  {PLAT} ({PLAT_VERSION}-{own}) sha256=")),
        "a path gem's CHECKSUMS entry is bare:\n{lock}"
    );
    // The ledger records which patch built which tree, and the digests its
    // downloads passed.
    let state_path = proj.join(".socket/vendor/state.json");
    let ledger_entry = || {
        let state = std::fs::read_to_string(&state_path).unwrap();
        let state: serde_json::Value = serde_json::from_str(&state).unwrap();
        let entries = state["entries"].as_object().cloned();
        entries
            .and_then(|entries| entries.values().next().cloned())
            .unwrap_or_else(|| panic!("a ledger entry: {state}"))
    };
    let entry = ledger_entry();
    let recorded: Vec<serde_json::Value> = sorted
        .iter()
        .map(|platform| {
            let file = |ext: &str| {
                let leaf = format!("{PLAT}-{PLAT_VERSION}-{platform}.{ext}");
                std::fs::read(fixture.join("service").join(leaf)).unwrap()
            };
            serde_json::json!({
                "platform": platform,
                "uuid": build_uuid(UUID, platform),
                "gemIntegrity": sri(&file("gem")),
                "gemspecIntegrity": sri(&file("gemspec")),
            })
        })
        .collect();
    assert_eq!(entry["uuid"], UUID, "the entry is the gem patch's: {entry}");
    assert_eq!(
        entry["gemBuilds"],
        serde_json::Value::from(recorded),
        "the ledger records each tree's patch: {entry}"
    );
    assert!(entry.get("gemPlatforms").is_none(), "{entry}");
    // For a person: one package, then nothing to do.
    let (code, stdout, stderr) = vendor_in(&unvendored, &server, false);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Vendored 1 package."), "{stdout}");
    let (code, stdout, stderr) = vendor_in(&unvendored, &server, false);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("1 package is already vendored; nothing to do."),
        "{stdout}"
    );

    // 4. VEX attests each platform gem against the committed trees, under
    //    the patch of its tree, and `--check` covers every one of them.
    let vex_path = proj.join("out.vex.json");
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vex",
            "--cwd",
            proj.to_str().unwrap(),
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            PRODUCT,
        ],
    );
    assert_eq!(code, 0, "vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "the vendored patch must be attested: {doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    for platform in &platforms {
        let part = format!(
            "Patched via Socket patch {} (vendored)",
            build_uuid(UUID, platform)
        );
        assert!(
            impact.split("; ").any(|said| said == part),
            "{platform}: attested under the patch of its tree: {doc}"
        );
    }
    let check = |root: &Path| {
        let uri = server.uri();
        run_socket(
            root,
            &[
                "vendor",
                "--check",
                "--json",
                "--cwd",
                root.to_str().unwrap(),
                "--patch-server-url",
                &uri,
            ],
        )
    };
    let (code, stdout, stderr) = check(&proj);
    assert_eq!(
        code, 0,
        "vendor --check failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        platform_gem_events(&parse_json_envelope(&stdout), "verified"),
        per_platform_gem(&sorted, "vendor_check_ok"),
        "one verdict per platform gem:\n{stdout}"
    );
    let tampered = base.join("tampered");
    common::fs_tree::copy_tree(&proj, &tampered);
    std::fs::write(
        tampered
            .join(&copy_rel)
            .join(&foreign[0])
            .join("lib/sockplat.rb"),
        PLAT_PRISTINE,
    )
    .unwrap();
    let (code, stdout, stderr) = check(&tampered);
    assert_ne!(
        code, 0,
        "an unpatched tree of a FOREIGN platform must fail the check.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // 5. FRESH CHECKOUT: only the committable files, and no patch service.
    let fresh = base.join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&gemfile_path, fresh.join("Gemfile")).unwrap();
    std::fs::copy(&lock_path, fresh.join("Gemfile.lock")).unwrap();
    common::fs_tree::copy_tree(&proj.join(".socket"), &fresh.join(".socket"));
    common::fs_tree::copy_tree(&proj.join(".bundle"), &fresh.join(".bundle"));
    let lock_wired = std::fs::read(&lock_path).unwrap();
    let served_before = service_requests(&server).await;
    let ci = bundle(&fresh, &["install"], true);
    assert!(
        ci.status.success(),
        "fresh-checkout frozen `bundle install` must succeed from the vendored trees.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    assert_eq!(
        std::fs::read(fresh.join("Gemfile.lock")).unwrap(),
        lock_wired,
        "frozen install must leave the committed Gemfile.lock byte-identical"
    );
    let script = format!(
        "require \"{declared}\"\n\
         abort \"probe constant missing after require\" unless defined?(Sockplat::SOCKET_PATCH_VENDOR_E2E)\n\
         puts Sockplat::SOCKET_PATCH_VENDOR_E2E\n\
         loaded = $LOADED_FEATURES.grep(%r{{/sockplat\\.rb\\z}})\n\
         puts loaded\n\
         puts \"build=\" + File.read(File.join(File.dirname(loaded.first), \"sockplat/build\"))"
    );
    let probe = bundle(&fresh, &["exec", "ruby", "-e", script.as_str()], false);
    assert!(
        probe.status.success(),
        "bundle exec runtime probe failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr),
    );
    let probe_out = String::from_utf8_lossy(&probe.stdout).into_owned();
    assert!(
        probe_out.contains(UUID),
        "probe constant must carry the patch uuid:\n{probe_out}"
    );
    assert!(
        probe_out.contains(&format!("{copy_rel}/{own}/lib/sockplat.rb")),
        "the patched file must load from the tree of the running platform:\n{probe_out}"
    );
    assert!(
        probe_out.contains(&format!("build={own}")),
        "that tree is this machine's own platform gem:\n{probe_out}"
    );
    // The lock is the one bundler itself writes for this Gemfile: an
    // unfrozen install and a re-lock leave it byte-identical.
    for args in [&["install"][..], &["lock"][..]] {
        let regen = bundle(&fresh, args, false);
        assert!(
            regen.status.success(),
            "`bundle {}` over the vendored pair failed:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&regen.stderr)
        );
        assert_eq!(
            std::fs::read(fresh.join("Gemfile.lock")).unwrap(),
            lock_wired,
            "`bundle {}` must regenerate the committed lock byte for byte (bundler {})",
            args.join(" "),
            bundler.version
        );
    }
    assert_eq!(
        service_requests(&server).await,
        served_before,
        "the fresh checkout installs with no request to the patch service"
    );

    // Manifest-less VEX over the fresh checkout: each platform gem is
    // attested under the patch of its tree from the lock's PATH wiring and
    // the vendor ledger, which records those patches. With the ledgers
    // gone too nothing says which patch built which tree, and the gem is
    // attested as itself from the lock and the patch API alone (the
    // platform trees are then read off the committed directory). On a
    // plain thread: PatchApi runs its own runtime, which cannot be started
    // (or dropped) from inside this test's async context.
    std::thread::scope(|scope| {
        scope.spawn(|| {
            use vex_e2e_common::{
                assert_attested, patch_view, run_vex, strip_ledgers, strip_manifest, Marker,
                PatchApi, VexRun,
            };
            let api = PatchApi::start(vec![(
                UUID.into(),
                patch_view(
                    UUID,
                    &purl,
                    &[("lib/sockplat.rb", &git_sha256(patched.as_bytes()))],
                    VULNS,
                ),
            )]);
            let run = |base: VexRun| VexRun {
                product: Some(PRODUCT.into()),
                ..base
            };
            strip_manifest(&fresh);
            let out = run_vex(&binary(), &fresh, &run(VexRun::offline()));
            assert_eq!(out.code, Some(0), "manifest-less vex: {out}");
            for platform in &platforms {
                assert_attested(
                    out.doc(),
                    &platform_purl(platform),
                    &build_uuid(UUID, platform),
                    Marker::Vendored,
                    VULNS,
                );
            }
            let base_purl = format!("pkg:gem/{PLAT}@{PLAT_VERSION}");
            strip_ledgers(&fresh);
            let out = run_vex(&binary(), &fresh, &run(VexRun::online(&api)));
            assert_eq!(out.code, Some(0), "ledger-less vex: {out}");
            assert_attested(out.doc(), &base_purl, UUID, Marker::Vendored, VULNS);
        });
    });

    // 6. A second run changes nothing and asks the service nothing.
    let gemfile_wired = std::fs::read(&gemfile_path).unwrap();
    let state_wired = std::fs::read(&state_path).unwrap();
    let (code, stdout, stderr) = vendor(&server);
    assert_eq!(
        code, 0,
        "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env2 = parse_json_envelope(&stdout);
    assert_eq!(env2["summary"]["failed"], 0, "re-run must not fail: {env2}");
    assert_eq!(
        platform_gem_events(&env2, "skipped"),
        per_platform_gem(&sorted, "already_vendored"),
        "{env2}"
    );
    assert_eq!(std::fs::read(&gemfile_path).unwrap(), gemfile_wired);
    assert_eq!(std::fs::read(&lock_path).unwrap(), lock_wired);
    assert_eq!(std::fs::read(&state_path).unwrap(), state_wired);
    assert_eq!(
        service_requests(&server).await,
        served_before,
        "an in-sync re-run downloads nothing"
    );

    // A newer patch of the gem that lacks one platform's patched build:
    // the vendored patch stays in force, and the run says so in one line
    // and does not fail.
    let manifest_path = proj.join(".socket/manifest.json");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    std::fs::write(&manifest_path, manifest.replace(UUID, UUID_NEXT)).unwrap();
    let update =
        platform_patch_service(&fixture, &purl, UUID_NEXT, with_build, without_build).await;
    let (code, stdout, stderr) = vendor(&update);
    assert_eq!(
        code, 0,
        "an update that lacks a platform is no failure.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env3 = parse_json_envelope(&stdout);
    assert_eq!(env3["summary"]["failed"], 0, "nothing failed: {env3}");
    let kept = env3["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["errorCode"] == "vendor_prebuilt_platform_pending")
        .unwrap_or_else(|| panic!("a vendor_prebuilt_platform_pending event: {env3}"));
    assert_eq!(kept["action"], "skipped", "{kept}");
    assert_eq!(
        kept["reason"],
        format!(
            "{PLAT}@{PLAT_VERSION} was not brought up to date: no patched build yet for {} ({} \
             and {} have one). Vendored mode needs every locked platform; its vendored copy of \
             an earlier patch stays in force as it is.",
            without_build[0], have[0], have[1]
        )
        .as_str(),
        "{kept}"
    );
    assert_eq!(std::fs::read(&gemfile_path).unwrap(), gemfile_wired);
    assert_eq!(std::fs::read(&lock_path).unwrap(), lock_wired);
    assert_eq!(std::fs::read(&state_path).unwrap(), state_wired);
    assert!(
        !proj
            .join(format!(".socket/vendor/gem/{UUID_NEXT}"))
            .exists(),
        "nothing of the newer patch is written"
    );
    assert_eq!(artifact_downloads(&update).await, Vec::<String>::new());
    drop(update);
    std::fs::write(&manifest_path, manifest).unwrap();

    // 7. An entry that names the platforms of its copy and no patch for
    //    their trees, as a development build recorded it: it still checks
    //    (one verdict, for the gem) and reverts, and the next vendor run
    //    records the patch of each tree in its place.
    let mut state: serde_json::Value = serde_json::from_slice(&state_wired).unwrap();
    for entry in state["entries"].as_object_mut().unwrap().values_mut() {
        let entry = entry.as_object_mut().unwrap();
        entry.remove("gemBuilds");
        entry.insert("gemPlatforms".into(), serde_json::json!(sorted));
    }
    let earlier_state = serde_json::to_vec_pretty(&state).unwrap();
    std::fs::write(&state_path, &earlier_state).unwrap();
    let (code, stdout, stderr) = check(&proj);
    assert_eq!(
        code, 0,
        "an entry that names platforms only still checks.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let checked = parse_json_envelope(&stdout);
    assert_eq!(checked["summary"]["verified"], 1, "{checked}");
    assert_eq!(
        platform_gem_events(&checked, "verified"),
        Vec::new(),
        "one verdict, for the gem: {checked}"
    );
    let reverting = base.join("reverting");
    common::fs_tree::copy_tree(&proj, &reverting);
    let (code, stdout, stderr) = run_socket(
        &reverting,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            reverting.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "an entry that names platforms only still reverts.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read(reverting.join("Gemfile")).unwrap(),
        gemfile_before
    );
    assert_eq!(
        std::fs::read(reverting.join("Gemfile.lock")).unwrap(),
        lock_before
    );
    assert!(!reverting.join(".socket/vendor").exists());
    let converting = service_requests(&server).await;
    let (code, stdout, stderr) = vendor(&server);
    assert_eq!(
        code, 0,
        "the run that converts the entry.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let converted = parse_json_envelope(&stdout);
    assert_eq!(
        platform_gem_events(&converted, "applied"),
        per_platform_gem(&sorted, ""),
        "{converted}"
    );
    let rebuilt = converted["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["errorCode"] == "vendor_artifact_rebuilt")
        .unwrap_or_else(|| panic!("a vendor_artifact_rebuilt event: {converted}"));
    assert!(
        rebuilt["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("was recorded with no patch named for its platform gems"),
        "{rebuilt}"
    );
    assert!(
        service_requests(&server).await > converting,
        "the trees are fetched again, each from its platform's patch"
    );
    assert_eq!(
        std::fs::read(&state_path).unwrap(),
        state_wired,
        "the ledger is the one a vendor run writes"
    );
    assert_eq!(std::fs::read(&gemfile_path).unwrap(), gemfile_wired);
    assert_eq!(std::fs::read(&lock_path).unwrap(), lock_wired);

    // 8. Revert: both files byte for byte, every tree gone.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_json_envelope(&stdout);
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&gemfile_path).unwrap(),
        gemfile_before,
        "revert must restore the Gemfile byte for byte"
    );
    assert_eq!(
        String::from_utf8(std::fs::read(&lock_path).unwrap()).unwrap(),
        lock_text,
        "revert must restore Gemfile.lock byte for byte"
    );
    assert!(!proj.join(".socket/vendor").exists());
}
