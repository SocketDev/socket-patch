#![cfg(feature = "cargo")]
//! Real-cargo capstone e2e for `socket-patch vendor` — the committability
//! proof for the `[patch.crates-io]` + Cargo.lock-surgery wiring.
//!
//! Drives the REAL cargo toolchain (network used for fixture setup only):
//!   1. A tiny consumer crate depending on the dep-free `cfg-if` is built
//!      with a private CARGO_HOME, populating `registry/src/` and Cargo.lock.
//!   2. A `.socket/` manifest + blob is staged whose hashes are computed from
//!      the ACTUAL extracted registry sources. The patch appends a
//!      `///`-documented `pub fn socket_patched() -> u32 { 1 }` — the doc
//!      comment is load-bearing: path deps build WITHOUT `--cap-lints allow`,
//!      and cfg-if's own `#![deny(missing_docs)]` fires on undocumented items
//!      (spike-verified).
//!   3. `socket-patch vendor --json --offline` — asserts the patched copy at
//!      `.socket/vendor/cargo/<uuid>/cfg-if-<ver>/`, the `[patch.crates-io]`
//!      entry in `.cargo/config.toml`, and the surgical lock detach (the
//!      `[[package]]` entry keeps name+version but loses source+checksum).
//!   4. COMPILE ORACLE: the consumer's `main.rs` is rewritten to call
//!      `cfg_if::socket_patched()` — it only compiles if the patched bytes
//!      are what cargo links — and `cargo run --locked --offline` prints it.
//!   5. **Fresh-checkout proof**: copy ONLY the committable files
//!      (Cargo.toml + Cargo.lock + .cargo/ + src/ + .socket/) to a new dir
//!      and `cargo build --locked --offline` with an EMPTY CARGO_HOME — and
//!      assert that CARGO_HOME gained no `registry/` (zero crate downloads).
//!   6. **Revert proof**: `vendor --revert` restores Cargo.lock byte-for-byte
//!      and removes `.socket/vendor/` + the managed `[patch]` entry.
//!
//! Skips (println) when `cargo` is missing or crates.io is unreachable for
//! the fixture build; all assertions after that are hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

const UUID: &str = "2b3c4d5e-6f70-4a1b-8c2d-0123456789ab";
const DEP: &str = "cfg-if";
/// Appended to the dep's `src/lib.rs`. Doc comment required: cfg-if denies
/// `missing_docs` and path deps get no `--cap-lints allow`.
const PATCH_SUFFIX: &str =
    "\n/// Socket-patch capstone marker (added by the vendored patch).\npub fn socket_patched() -> u32 { 1 }\n";

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

/// Run socket-patch with ambient `SOCKET_*` vars scrubbed and the fixture's
/// private CARGO_HOME injected (the cargo crawler resolves the registry
/// source tree through it).
fn run_socket(cwd: &Path, args: &[&str], cargo_home: &Path) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env("CARGO_HOME", cargo_home);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn cargo(cwd: &Path, args: &[&str], cargo_home: &Path) -> Output {
    Command::new("cargo")
        .args(args)
        .current_dir(cwd)
        .env("CARGO_HOME", cargo_home)
        // The assertions read `<fixture>/target/debug/...`; an ambient
        // CARGO_TARGET_DIR (shared-build-cache setups) would redirect the
        // child build elsewhere and break them.
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("failed to run cargo")
}

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn stage_patch(proj: &Path, purl: &str, file_key: &str, before: &[u8], after: &[u8]) {
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
            "vulnerabilities": {},
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

/// The locked version of `name` in Cargo.lock (first `[[package]]` match).
fn locked_version(lock_text: &str, name: &str) -> Option<String> {
    let needle = format!("name = \"{name}\"");
    let mut lines = lock_text.lines();
    while let Some(line) = lines.next() {
        if line.trim() == needle {
            for l in lines.by_ref() {
                let t = l.trim();
                if let Some(v) = t.strip_prefix("version = \"") {
                    return Some(v.trim_end_matches('"').to_string());
                }
                if t == "[[package]]" {
                    break;
                }
            }
        }
    }
    None
}

/// The full `[[package]]` block (text) for `name` in Cargo.lock.
fn package_block(lock_text: &str, name: &str) -> Option<String> {
    let needle = format!("name = \"{name}\"");
    lock_text
        .split("[[package]]")
        .find(|block| block.lines().any(|l| l.trim() == needle))
        .map(str::to_string)
}

/// Find the extracted registry source dir `<cargo_home>/registry/src/<idx>/<name>-<ver>/`.
fn find_registry_crate(cargo_home: &Path, leaf: &str) -> Option<PathBuf> {
    let src = cargo_home.join("registry").join("src");
    for entry in std::fs::read_dir(&src).ok()? {
        let candidate = entry.ok()?.path().join(leaf);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

/// Stage the consumer project + private CARGO_HOME and run the baseline
/// build (which extracts cfg-if into `registry/src/`). Returns
/// `(proj, cargo_home, locked cfg-if version, registry src dir)` or `None`
/// when the toolchain/network makes the fixture impossible (caller skips).
fn stage_fixture(tmp: &Path) -> Option<(PathBuf, PathBuf, String, PathBuf)> {
    let proj = tmp.join("proj");
    let cargo_home = tmp.join("cargo-home");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(
        proj.join("Cargo.toml"),
        format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{DEP} = \"1.0\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        proj.join("src/main.rs"),
        "fn main() { println!(\"baseline\"); }\n",
    )
    .unwrap();

    let build = cargo(&proj, &["build", "-q"], &cargo_home);
    if !build.status.success() {
        println!(
            "SKIP e2e_vendor_cargo_build: baseline `cargo build` failed (crates.io \
             unreachable?):\n{}",
            String::from_utf8_lossy(&build.stderr)
        );
        return None;
    }

    let lock_text = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    let version = locked_version(&lock_text, DEP)
        .unwrap_or_else(|| panic!("Cargo.lock must lock {DEP}:\n{lock_text}"));
    let crate_dir =
        find_registry_crate(&cargo_home, &format!("{DEP}-{version}")).unwrap_or_else(|| {
            panic!(
                "{DEP}-{version} must be extracted under <CARGO_HOME>/registry/src after the build"
            )
        });
    Some((proj, cargo_home, version, crate_dir))
}

// ── the capstone ──────────────────────────────────────────────────────

#[test]
fn cargo_vendor_fresh_checkout_locked_offline_build_and_revert() {
    if !has_command("cargo") {
        println!("SKIP e2e_vendor_cargo_build: `cargo` not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path()) else {
        return; // skip already printed
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let copy_rel = format!(".socket/vendor/cargo/{UUID}/{DEP}-{version}");

    // Manifest + blob from the ACTUAL extracted registry bytes.
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, "src/lib.rs", &orig, &patched);

    let lock_path = proj.join("Cargo.lock");
    let lock_before = std::fs::read(&lock_path).unwrap();

    // Vendor (offline; blob staged locally).
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &cargo_home,
    );
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");
    // NOTE: summary.applied / the event action are asserted in the
    // `cargo_vendor_reports_applied_event` below — a successful
    // cargo vendor is currently misreported as skipped/`vendored` (see the
    // BUG note there). The on-disk + build assertions here are unaffected.

    // The patched copy, without a `.cargo-checksum.json` (path deps must
    // never carry one).
    let copy_lib = proj.join(&copy_rel).join("src/lib.rs");
    assert_eq!(
        std::fs::read(&copy_lib).unwrap(),
        patched,
        "vendored copy must hold the patched bytes"
    );
    assert!(
        !proj.join(&copy_rel).join(".cargo-checksum.json").exists(),
        "a path-dep copy must not carry .cargo-checksum.json"
    );
    // The pristine registry source is untouched (vendor copies, never mutates).
    assert_eq!(
        std::fs::read(crate_dir.join("src/lib.rs")).unwrap(),
        orig,
        "registry source must stay pristine"
    );
    assert!(
        proj.join(format!(
            ".socket/vendor/cargo/{UUID}/socket-patch.vendor.json"
        ))
        .is_file(),
        "informational vendor marker missing"
    );

    // `[patch.crates-io]` entry in .cargo/config.toml points at the copy.
    let config = std::fs::read_to_string(proj.join(".cargo/config.toml"))
        .expect("vendor must create .cargo/config.toml");
    assert!(
        config.contains("[patch.crates-io]"),
        "config must carry [patch.crates-io]:\n{config}"
    );
    assert!(
        config.contains(&copy_rel),
        "patch entry must point at the uuid copy path:\n{config}"
    );

    // Lock surgery: the entry keeps name+version but loses source+checksum
    // (without this, `cargo build --locked` fails closed on the [patch]).
    let lock_text = std::fs::read_to_string(&lock_path).unwrap();
    let block = package_block(&lock_text, DEP).expect("cfg-if lock entry must survive");
    assert!(
        block.contains(&format!("version = \"{version}\"")),
        "lock entry keeps the version:\n{block}"
    );
    assert!(
        !block.contains("source = ") && !block.contains("checksum = "),
        "lock entry must be detached from the registry (no source/checksum):\n{block}"
    );

    // COMPILE ORACLE: the consumer references the patched-only symbol.
    std::fs::write(
        proj.join("src/main.rs"),
        "fn main() { println!(\"MARKER:{}\", cfg_if::socket_patched()); }\n",
    )
    .unwrap();
    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    assert!(
        run.status.success(),
        "in-place `cargo run --locked --offline` must link the vendored patch.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    );
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("MARKER:1"),
        "patched symbol must be linked: {}",
        String::from_utf8_lossy(&run.stdout)
    );

    // FRESH-CHECKOUT PROOF: only the committable files, EMPTY CARGO_HOME,
    // --locked --offline (spike claim 3).
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("Cargo.toml"), fresh.join("Cargo.toml")).unwrap();
    std::fs::copy(&lock_path, fresh.join("Cargo.lock")).unwrap();
    copy_dir_recursive(&proj.join(".cargo"), &fresh.join(".cargo"));
    copy_dir_recursive(&proj.join("src"), &fresh.join("src"));
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_home = tmp.path().join("fresh-cargo-home");
    std::fs::create_dir_all(&fresh_home).unwrap();
    let build = cargo(
        &fresh,
        &["build", "-q", "--locked", "--offline"],
        &fresh_home,
    );
    assert!(
        build.status.success(),
        "fresh-checkout `cargo build --locked --offline` (empty CARGO_HOME) must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr),
    );
    let bin = Command::new(fresh.join("target/debug/consumer"))
        .output()
        .expect("run fresh consumer binary");
    assert!(
        String::from_utf8_lossy(&bin.stdout).contains("MARKER:1"),
        "fresh build must link the PATCHED dep: {}",
        String::from_utf8_lossy(&bin.stdout)
    );
    // Zero registry/network access: the empty CARGO_HOME gained no crate
    // sources (cargo only writes its dotfile bookkeeping caches).
    assert!(
        !fresh_home.join("registry").exists(),
        "fresh CARGO_HOME must not gain a registry/ — the vendored path dep \
         is the sole provider"
    );

    // Idempotency: re-vendor leaves the lock byte-stable.
    let lock_wired = std::fs::read(&lock_path).unwrap();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &cargo_home,
    );
    assert_eq!(
        code, 0,
        "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "re-vendor must leave Cargo.lock byte-identical"
    );

    // REVERT PROOF.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &cargo_home,
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "revert must restore Cargo.lock byte-identical to the pre-vendor snapshot"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
    // The managed [patch] entry is gone (vendor created the config, so the
    // whole file is removed; tolerate an empty leftover that lost the entry).
    let config_after = std::fs::read_to_string(proj.join(".cargo/config.toml")).unwrap_or_default();
    assert!(
        !config_after.contains(DEP),
        "revert must drop the managed [patch.crates-io] entry:\n{config_after}"
    );
}

/// Correct-behavior pin for the vendor envelope: a successful first-time
/// cargo vendor must surface as an `applied` event with `summary.applied == 1`
/// (CLI_CONTRACT.md: vendor events are `Applied` (= vendored)).
///
/// Currently it is misreported as `skipped` with errorCode `vendored` and
/// `summary.applied == 0`: the shared `result_to_event` (apply.rs) routes any
/// result whose `package_path` contains `.socket/vendor/` to the
/// Skipped/`vendored` event — that check exists for APPLY's yield-to-vendor
/// path, but the cargo/golang/composer/gem vendor backends set their
/// `ApplyResult.package_path` to the vendor copy dir itself, so vendor's own
/// successes trip it (npm/pypi report `applied` correctly because their
/// package_path is a stage tempdir / site-packages). Human output says
/// "Vendored 0 package(s); 1 skipped" and `track_patch_vendored` reports 0.
#[test]
fn cargo_vendor_reports_applied_event() {
    if !has_command("cargo") {
        println!("SKIP: `cargo` not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path()) else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, "src/lib.rs", &orig, &patched);

    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &cargo_home,
    );
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(
        env["summary"]["applied"], 1,
        "a successful first-time vendor must count as applied: {env}"
    );
    let event = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["purl"] == purl.as_str())
        .unwrap_or_else(|| panic!("expected an event for {purl}: {env}"));
    assert_eq!(
        event["action"], "applied",
        "vendor success must be an `applied` event, not skipped/`vendored`: {event}"
    );
}
