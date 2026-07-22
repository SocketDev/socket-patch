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
//! Skips (with a println) when `bundle`/`ruby` are missing, when the host
//! bundler predates the spike-verified 2.5 floor (macOS ships a 1.17-era
//! bundler whose lock grammar the pair edit was never validated against), or
//! when the fixture install cannot reach rubygems.org; every assertion after
//! that is hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

/// Canonical lowercase patch uuid (a dedicated path level under
/// `.socket/vendor/gem/`) — also the probe constant's runtime value.
const UUID: &str = "3c4d5e6f-7a8b-4a1b-8c2d-0123456789ab";
const DEP: &str = "rack";
const GHSA: &str = "GHSA-vend-gem-host";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// `bundle --version` → `(major, minor)`. `None` when the probe fails to run
/// or parse (treated as "no usable bundler" by the caller).
fn bundler_version() -> Option<(u32, u32)> {
    let out = Command::new("bundle").arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    // "Bundler version 2.7.2" — the version is the last whitespace token.
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let ver = text.split_whitespace().last()?.to_string();
    let mut it = ver.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
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

// ── the capstone ──────────────────────────────────────────────────────

#[test]
#[ignore = "host capstone: shells out to a real bundler >= 2.5; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn gem_vendor_fresh_checkout_bundle_install_and_revert() {
    if !has_command("ruby") {
        println!("SKIP e2e_vendor_gem_build: `ruby` not installed");
        return;
    }
    let Some((major, minor)) = bundler_version() else {
        println!("SKIP e2e_vendor_gem_build: `bundle` not installed (or version unparseable)");
        return;
    };
    // The pair-edit lock grammar was spike-verified on bundler 2.5+; macOS
    // ships a 1.17-era bundler whose lock form this suite has no claim about.
    if major < 2 || (major == 2 && minor < 5) {
        println!(
            "SKIP e2e_vendor_gem_build: host bundler {major}.{minor} predates the \
             spike-verified 2.5 floor"
        );
        return;
    }

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
        &["config", "set", "--local", "path", "vendor/bundle"],
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
    let api = Command::new("ruby")
        .args(["-e", "puts Gem.ruby_api_version"])
        .output()
        .expect("failed to run ruby");
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
