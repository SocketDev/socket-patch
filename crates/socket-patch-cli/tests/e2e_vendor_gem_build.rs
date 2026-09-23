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
//! `vendor` run by construction — manifest + `.socket/vendor/` artifact +
//! ledger + the mandatory Gemfile/lock pair edit, but NO `.socket/blobs`
//! (get's vendored download phase holds content in memory).
//!
//! MANIFEST-LESS VEX (every capstone, `vendored_manifestless_vex_matrix`,
//! on the fresh checkout after its frozen install): manifest deleted →
//! `vex --offline` attests `(vendored)` from the lock's PATH wiring + the
//! vendor ledger; both ledgers deleted → still attested from the lock +
//! the patch API (and by the embedded `apply --vex` / `vendor --vex`,
//! which touch nothing); `--offline` without ledgers → `record_unavailable`
//! with zero requests; lock-only revert (Gemfile keeps `path:`) → still
//! attested, and the real bundler re-wires the PATH section on the next
//! unfrozen install (a frozen one refuses the pair); full registry revert
//! (ledgers + artifact kept) → `vendor_unwired`, also under `--no-verify`.
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

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
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

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

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

/// Run the socket-patch binary with a scrubbed environment: every ambient
/// `SOCKET_*` var is removed (so a developer's `SOCKET_DRY_RUN=1` etc. can't
/// flip behavior) along with `VIRTUAL_ENV` (crawler discovery input).
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

/// Run `bundle <args>` in `cwd` with the ambient `BUNDLE_*`/`GEM_*` state
/// scrubbed (a developer's global bundler config — a different BUNDLE_PATH,
/// frozen mode, a custom gem home — must not leak into the fixture) and
/// `BUNDLE_APP_CONFIG` pinned to the project's own `.bundle/` so
/// `bundle config set --local` writes a real committable file.
fn bundle(cwd: &Path, args: &[&str], frozen: bool) -> Output {
    let mut cmd = Command::new("bundle");
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        let key = k.to_string_lossy().into_owned();
        if key.starts_with("BUNDLE_") || key.starts_with("GEM_") {
            cmd.env_remove(&k);
        }
    }
    // After the `BUNDLE_*`/`GEM_*` scrub, which would otherwise take the
    // sandbox's own BUNDLE_USER_HOME / GEM_SPEC_CACHE straight back out.
    cache_env::isolate(&mut cmd);
    cmd.env("BUNDLE_APP_CONFIG", cwd.join(".bundle"));
    if frozen {
        cmd.env("BUNDLE_FROZEN", "true");
    }
    cmd.output().expect("failed to run bundle")
}

/// Git-blob SHA-256 (`sha256("blob <len>\0" ++ bytes)`) — the hash format
/// socket-patch records in manifests.
fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
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

fn parse_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("vendor --json output is not JSON: {e}\nstdout:\n{stdout}"))
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

/// Manifest-less VEX over a vendored checkout, the depscan / `vendor
/// --detached` shape:
///
///   1. `.socket/manifest.json` deleted: `vex --offline` attests
///      `(vendored)` from the lock's `PATH` wiring + the vendor ledger's
///      embedded record, hash-verified against the committed artifact;
///   2. both ledgers deleted too: still attested — discovery reads the lock,
///      the record comes from the patch API; the embedded `apply --vex` and
///      `vendor --vex` agree and touch nothing;
///   3. `--offline` with no ledgers: `record_unavailable`, ZERO requests;
///   4. lock-only revert (the Gemfile keeps `path:`): still attested with
///      the ledger — the REAL bundler re-resolves the gem from the path on
///      the next unfrozen install (a frozen one refuses the pair), after
///      which the ledger-less lock attests again;
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
    copy_dir_recursive(&fresh.join(".socket"), &copy.join(".socket"));
    copy_dir_recursive(v.committed_bundle, &copy.join(".bundle"));
    for f in std::fs::read_dir(&saved).unwrap() {
        let f = f.unwrap();
        std::fs::copy(f.path(), copy.join(".socket/vendor").join(f.file_name())).unwrap();
    }
    let out = run_vex(&bin, &copy, &run(VexRun::offline()));
    assert_eq!(
        out.code,
        Some(0),
        "Gemfile `path:` kept, lock reverted, ledger kept: {out}\n{ctx}"
    );
    assert_attested(out.doc(), v.purl, UUID, Marker::Vendored, VULNS);
    let frozen = bundle(&copy, &["install"], true);
    assert!(
        !frozen.status.success(),
        "a frozen install must refuse the Gemfile/lock disagreement (bundler {})",
        v.bundler.version
    );
    // Bundler <= 2.0 persisted `BUNDLE_FROZEN: "true"` into the copy's
    // `.bundle/config` on that frozen attempt; a developer's unfrozen
    // install runs from the committed config.
    copy_dir_recursive(v.committed_bundle, &copy.join(".bundle"));
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
    let env = parse_envelope(&stdout);
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

    // 5. FRESH-CHECKOUT PROOF: ONLY the committable files, frozen lock. The
    //    vendored path source is the only provider of rack (the fresh dir
    //    has no vendor/bundle), and the patched constant must be visible at
    //    `require` time from the vendored path.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&gemfile_path, fresh.join("Gemfile")).unwrap();
    std::fs::copy(&lock_path, fresh.join("Gemfile.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    copy_dir_recursive(&proj.join(".bundle"), &fresh.join(".bundle"));
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
    let env2 = parse_envelope(&stdout);
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
    let renv = parse_envelope(&stdout);
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
    let env = parse_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");

    // The appended managed block, byte-exact (hand-pinned marker lines — the
    // block delimits what revert may delete, so its shape is contract).
    let copy_rel = format!(".socket/vendor/gem/{UUID}/{DEP}-{version}");
    let gemfile = std::fs::read_to_string(&gemfile_path).unwrap();
    let expected_gemfile = format!(
        "{}# >>> socket-patch vendor (managed) >>>\ngem \"{DEP}\", \"{version}\", \
         path: \"{copy_rel}\"\n# <<< socket-patch vendor (managed) <<<\n",
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
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    copy_dir_recursive(&proj.join(".bundle"), &fresh.join(".bundle"));
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
    let env2 = parse_envelope(&stdout);
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
    let renv = parse_envelope(&stdout);
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
/// as a plain `vendor` run — manifest record, `.socket/vendor/` artifact +
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
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
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
        })))
        .mount(&server)
        .await;
    let api_url = server.uri();

    let gemfile_path = proj.join("Gemfile");
    let gemfile_before = std::fs::read(&gemfile_path).unwrap();

    // 3. get <uuid> --mode vendored: record save + scan's whole-manifest
    //    vendor step in one command. `--vendor-source build` keeps the
    //    artifact build local (no vendoring-service mocks needed); the
    //    staging fetches the blob content into MEMORY from the view mock.
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
            "build",
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
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["found"], 1, "envelope: {env}");
    assert_eq!(env["downloaded"], 1, "envelope: {env}");
    // get's vendored envelope (CLI_CONTRACT.md "get --mode and installed
    // narrowing"): `applied` is dropped (structurally zero — nothing is
    // applied in place), and the vendor Envelope nests under "vendor".
    assert!(
        env.get("applied").is_none(),
        "get --mode vendored must drop the `applied` key: {env}"
    );
    assert_eq!(env["patches"][0]["purl"], purl.as_str(), "envelope: {env}");
    assert_eq!(env["patches"][0]["uuid"], UUID, "envelope: {env}");
    assert_eq!(
        env["vendor"]["summary"]["applied"], 1,
        "one package vendored: {env}"
    );
    assert_eq!(
        env["vendor"]["summary"]["failed"], 0,
        "no vendor failures: {env}"
    );
    let applied = env["vendor"]["events"]
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
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    copy_dir_recursive(&proj.join(".bundle"), &fresh.join(".bundle"));
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
}
