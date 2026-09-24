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
//! A get-driven twin (`cargo_get_uuid_vendored_fresh_checkout_locked_build`,
//! v3.6) reaches the same committed state through `get <uuid> --mode
//! vendored` with the patch record + blob content served from a wiremock
//! view endpoint instead of a pre-staged `.socket/` — proving the manifest
//! write, the NO-blobs posture (content stays in memory), and the same
//! fresh-checkout `--locked --offline` build (the revert half is covered by
//! the capstone: get rides the identical vendor engine).
//!
//! MANIFEST-LESS VEX (both drivers), on the fresh checkout after its
//! `--locked --offline` build, with the shared `vex_e2e_common` helpers and
//! a separate patch-API stand-in: (1) `.socket/manifest.json` deleted, the
//! vendor ledger kept → `(vendored)` from the ledger's embedded record, zero
//! API calls, embedded `apply --vex` / `vendor --vex` too; (2) the ledgers
//! deleted → the `[patch.crates-io]` path + detached lock entry + committed
//! copy still attest with the API's record (embedded runs too); (3)
//! `--offline` with no ledger → `record_unavailable`, zero requests; (4)
//! `Cargo.lock` reverted to crates.io with ledger + copy kept — the stale
//! `[patch]` left behind, and the full revert (`[patch]` dropped) rebuilt
//! `--locked --offline` by the real cargo — → NOT attested
//! (`vendor_unwired`), also under `--no-verify`.
//!
//! Toolchain / lock format: `cargo_e2e_matrix` (`SOCKET_PATCH_CARGO_E2E_*`)
//! runs every cargo step under a pinned release and re-encodes the baseline
//! `Cargo.lock` as v1–v4 before vendoring; the detach must keep that format
//! and the fresh `--locked` build must accept it.
//!
//! Skips (println) when `cargo` is missing or crates.io is unreachable for
//! the fixture build (a failure instead under
//! `SOCKET_PATCH_CARGO_E2E_REQUIRED=1`); all assertions after that are hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "cargo_e2e_matrix/mod.rs"]
mod cargo_e2e_matrix;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
use vex_e2e_common::{
    assert_absent, assert_attested, assert_not_attested, run_vex, strip_ledgers, strip_manifest,
    Marker, PatchApi, VexRun, VexVia,
};

const ORG: &str = "test-org";
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

/// Run socket-patch with ambient `SOCKET_*` vars scrubbed and the fixture's
/// private CARGO_HOME injected (the cargo crawler resolves the registry
/// source tree through it).
fn run_socket(cwd: &Path, args: &[&str], cargo_home: &Path) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") && k.to_string_lossy() != "SOCKET_NO_CONFIG" {
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

/// Real cargo under the matrix's pinned toolchain (if any), the fixture's
/// private CARGO_HOME and no ambient CARGO_TARGET_DIR (the assertions read
/// `<fixture>/target/debug/...`).
fn cargo(cwd: &Path, args: &[&str], cargo_home: &Path) -> Output {
    cargo_e2e_matrix::cargo_command(cwd, cargo_home)
        .args(args)
        .output()
        .expect("failed to run cargo")
}

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
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
            "vulnerabilities": { "GHSA-vend-cargo-real": {
                "cves": ["CVE-2024-88888"],
                "summary": "capstone vex vuln",
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
/// when the toolchain/network makes the fixture impossible (caller skips;
/// `tag` names the calling test in the skip message).
fn stage_fixture(tmp: &Path, tag: &str) -> Option<(PathBuf, PathBuf, String, PathBuf)> {
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
        let _ = cargo_e2e_matrix::skip(
            &format!("e2e_vendor_cargo_build ({tag})"),
            &format!(
                "baseline `cargo build` failed (crates.io unreachable?):\n{}",
                String::from_utf8_lossy(&build.stderr)
            ),
        );
        return None;
    }
    // The matrix's lock format (v1–v4), re-encoded from what the toolchain
    // wrote: the committed-lockfile shape the detach must meet.
    cargo_e2e_matrix::apply_lock_version(&proj);

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

// ── manifest-less VEX (lockfile discovery) ────────────────────────────

const GHSA: &str = "GHSA-vend-cargo-real";
const CVE: &str = "CVE-2024-88888";

/// Everything the manifest-less steps need, owned (they run where no async
/// runtime is entered: the shared `PatchApi` brings its own).
struct ManifestlessVendored {
    /// The fresh checkout (its `--locked --offline` build already ran).
    fresh: PathBuf,
    fresh_home: PathBuf,
    /// A CARGO_HOME holding crates.io's pristine copy (the fixture build's),
    /// for the reverted checkout's offline build.
    registry_home: PathBuf,
    scratch: PathBuf,
    purl: String,
    patched: Vec<u8>,
    /// The pre-vendor (crates.io) `Cargo.lock`.
    baseline_lock: Vec<u8>,
}

impl ManifestlessVendored {
    /// Run [`Self::steps`] off the async runtime (and re-raise its panic).
    async fn run_async(self) {
        if let Err(e) = tokio::task::spawn_blocking(move || self.steps()).await {
            std::panic::resume_unwind(e.into_panic());
        }
    }

    fn vex_run(&self, api: &PatchApi, cargo_home: &Path) -> VexRun {
        VexRun {
            product: Some("pkg:cargo/app@1.0.0".to_string()),
            ..VexRun::online(api)
        }
        .env("CARGO_HOME", cargo_home)
    }

    fn steps(self) {
        let bin = binary();
        let vulns: &[(&str, &[&str])] = &[(GHSA, &[CVE])];
        let api = PatchApi::start(vec![(
            UUID.to_string(),
            vex_e2e_common::patch_view(
                UUID,
                &self.purl,
                &[("src/lib.rs", &vex_e2e_common::git_sha256(&self.patched))],
                vulns,
            ),
        )]);
        let fresh = self.fresh.as_path();
        let ledger_path = fresh.join(socket_patch_core::vendor::VENDOR_STATE_REL);
        let run = self.vex_run(&api, &self.fresh_home);
        let embedded = [VexVia::Apply, VexVia::Vendor];

        // (1) The manifest deleted (a detached / depscan checkout), the
        //     vendor ledger kept: its embedded record attests — no API.
        strip_manifest(fresh);
        assert!(ledger_path.is_file(), "the vendor ledger travels");
        let out = run_vex(&bin, fresh, &run);
        assert_eq!(out.code, Some(0), "(1) ledger-backed:\n{out}");
        assert_attested(out.doc(), &self.purl, UUID, Marker::Vendored, vulns);
        for via in embedded {
            let out = run_vex(&bin, fresh, &run.clone().via(via));
            assert_eq!(out.code, Some(0), "(1) {via:?} --vex:\n{out}");
            assert_eq!(out.envelope["status"], "noManifest", "(1) {via:?}:\n{out}");
            assert_attested(out.doc(), &self.purl, UUID, Marker::Vendored, vulns);
        }
        assert_eq!(
            api.view_requests(UUID),
            0,
            "(1) the ledger record needs no API"
        );

        // (2) Ledgers deleted: the `[patch.crates-io]` path + the detached
        //     lock entry + the committed copy, with the API's record.
        let ledger = std::fs::read(&ledger_path).unwrap();
        strip_ledgers(fresh);
        let out = run_vex(&bin, fresh, &run);
        assert_eq!(out.code, Some(0), "(2) lockfile-only:\n{out}");
        assert_attested(out.doc(), &self.purl, UUID, Marker::Vendored, vulns);
        assert!(
            api.view_requests(UUID) >= 1,
            "(2) the record came from the API"
        );
        for via in embedded {
            let out = run_vex(&bin, fresh, &run.clone().via(via));
            assert_eq!(out.code, Some(0), "(2) {via:?} --vex:\n{out}");
            assert_eq!(out.envelope["status"], "noManifest", "(2) {via:?}:\n{out}");
            assert_attested(out.doc(), &self.purl, UUID, Marker::Vendored, vulns);
        }
        assert!(
            !fresh.join(".socket/manifest.json").exists(),
            "no VEX step writes the manifest"
        );
        assert!(!ledger_path.exists(), "no VEX step writes the ledger");

        // (3) Offline with no ledger: nothing local holds the record.
        let before = api.request_count();
        let out = run_vex(
            &bin,
            fresh,
            &VexRun {
                offline: true,
                ..run.clone()
            },
        );
        assert_eq!(out.code, Some(1), "(3) offline:\n{out}");
        assert_not_attested(&out.envelope, &self.purl, "record_unavailable");
        assert_absent(out.doc.as_ref(), &self.purl);
        assert_eq!(api.request_count(), before, "(3) --offline made a request");

        // (4a) Cargo.lock reverted to crates.io, ledger + copy + the stale
        //      `[patch]` kept: the copy is not what the lock builds.
        std::fs::write(&ledger_path, &ledger).unwrap();
        std::fs::write(fresh.join("Cargo.lock"), &self.baseline_lock).unwrap();
        for no_verify in [false, true] {
            let out = run_vex(
                &bin,
                fresh,
                &VexRun {
                    no_verify,
                    ..run.clone()
                },
            );
            assert_eq!(out.code, Some(1), "(4a) no_verify={no_verify}:\n{out}");
            assert_not_attested(&out.envelope, &self.purl, "vendor_unwired");
            assert_absent(out.doc.as_ref(), &self.purl);
        }

        // (4b) The full revert (lock + `[patch]` dropped), ledger + copy
        //      kept, rebuilt for real from crates.io's copy.
        let revert = self.scratch.join("reverted");
        std::fs::create_dir_all(&revert).unwrap();
        for file in ["Cargo.toml", "Cargo.lock"] {
            std::fs::copy(fresh.join(file), revert.join(file)).unwrap();
        }
        copy_dir_recursive(&fresh.join("src"), &revert.join("src"));
        copy_dir_recursive(&fresh.join(".socket"), &revert.join(".socket"));
        std::fs::write(
            revert.join("src/main.rs"),
            "fn main() { println!(\"baseline\"); }\n",
        )
        .unwrap();
        let build = cargo(
            &revert,
            &["build", "-q", "--locked", "--offline"],
            &self.registry_home,
        );
        assert!(
            build.status.success(),
            "(4b) the reverted checkout builds from crates.io's copy:\n{}",
            String::from_utf8_lossy(&build.stderr)
        );
        assert!(
            revert.join(format!(".socket/vendor/cargo/{UUID}")).is_dir(),
            "(4b) the committed copy is still there"
        );
        let run = self.vex_run(&api, &self.registry_home);
        for no_verify in [false, true] {
            let out = run_vex(
                &bin,
                &revert,
                &VexRun {
                    no_verify,
                    ..run.clone()
                },
            );
            assert_eq!(out.code, Some(1), "(4b) no_verify={no_verify}:\n{out}");
            assert_not_attested(&out.envelope, &self.purl, "vendor_unwired");
            assert_absent(out.doc.as_ref(), &self.purl);
        }
    }
}

// ── the capstone ──────────────────────────────────────────────────────

#[test]
fn cargo_vendor_fresh_checkout_locked_offline_build_and_revert() {
    if !cargo_e2e_matrix::cargo_available("e2e_vendor_cargo_build (main)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path(), "main") else {
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

    // Real-toolchain VEX: attest the vendored patch against the copied crate
    // dir (the vendored-artifact verification path for a real cargo path-dep).
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
            "pkg:cargo/app@1.0.0",
        ],
        &cargo_home,
    );
    assert_eq!(code, 0, "vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let vex_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let vex_stmts = vex_doc["statements"].as_array().unwrap();
    assert_eq!(
        vex_stmts.len(),
        1,
        "vendored cargo patch must be attested: {vex_doc}"
    );
    assert_eq!(
        vex_stmts[0]["vulnerability"]["name"],
        "GHSA-vend-cargo-real"
    );
    assert_eq!(vex_stmts[0]["status"], "not_affected");
    assert_eq!(vex_stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    assert!(
        vex_stmts[0]["impact_statement"]
            .as_str()
            .unwrap()
            .contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {vex_doc}"
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
    assert_eq!(
        cargo_e2e_matrix::lock_format(&lock_text),
        cargo_e2e_matrix::lock_format(&String::from_utf8_lossy(&lock_before)),
        "the detach must keep the lock format:\n{lock_text}"
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

    // Manifest-less VEX on the fresh checkout.
    ManifestlessVendored {
        fresh: fresh.clone(),
        fresh_home: fresh_home.clone(),
        registry_home: cargo_home.clone(),
        scratch: tmp.path().join("manifestless"),
        purl: purl.clone(),
        patched: patched.clone(),
        baseline_lock: lock_before.clone(),
    }
    .steps();

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
    if !cargo_e2e_matrix::cargo_available("e2e_vendor_cargo_build (applied-event)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path(), "applied-event")
    else {
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

/// get-driven twin (v3.6): `get <uuid> --mode vendored --vendor-source build`
/// must reach the capstone's committed state through scan's vendored engine —
/// the manifest record, the patched copy under `.socket/vendor/cargo/<uuid>/`,
/// the `[patch.crates-io]` wiring + surgical lock detach — with NO
/// `.socket/blobs` (the download phase holds content in memory; the vendor
/// step re-fetches `blobContent` from the same view mock). Then the
/// fresh-checkout proof: only the committable files, EMPTY CARGO_HOME,
/// `cargo build --locked --offline` links the patched-only symbol with zero
/// crate downloads. The revert half is covered by the capstone — get rides
/// the identical vendor engine.
///
/// multi_thread: the CLI/cargo subprocesses block a worker thread while
/// wiremock keeps serving the view endpoint on the others.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_get_uuid_vendored_fresh_checkout_locked_build() {
    if !cargo_e2e_matrix::cargo_available("e2e_vendor_cargo_build (get-uuid)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path(), "get-uuid") else {
        return; // skip already printed
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let copy_rel = format!(".socket/vendor/cargo/{UUID}/{DEP}-{version}");
    let lock_before = std::fs::read(proj.join("Cargo.lock")).unwrap();

    // The view endpoint serves the record with REAL hashes computed from the
    // ACTUAL extracted registry bytes + inline blobContent — no `.socket/`
    // pre-staging: `get` writes the manifest itself and the vendor step
    // fetches the after-blob into memory from this same mock.
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    assert!(
        !String::from_utf8_lossy(&orig).contains("socket_patched"),
        "pristine registry sources must not carry the marker"
    );
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "src/lib.rs": {
                    "beforeHash": git_sha256(&orig),
                    "afterHash": git_sha256(&patched),
                    "blobContent": b64(&patched),
                }
            },
            "vulnerabilities": { "GHSA-vend-cargo-real": {
                "cves": ["CVE-2024-88888"],
                "summary": "capstone vex vuln",
                "severity": "high",
                "description": "d",
            }},
            "description": "capstone marker patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&server)
        .await;

    let server_uri = server.uri();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "get",
            UUID,
            "--mode",
            "vendored",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &server_uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--vendor-source",
            "build",
        ],
        &cargo_home,
    );
    assert_eq!(
        code, 0,
        "get --mode vendored failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["found"], 1, "envelope: {env}");
    assert_eq!(env["downloaded"], 1, "envelope: {env}");
    assert!(
        env["applied"].is_null(),
        "vendored get drops `applied` — nothing applies in place: {env}"
    );
    assert_eq!(
        env["vendor"]["summary"]["failed"], 0,
        "nested vendor envelope must report no failures: {env}"
    );

    // The download phase writes NOTHING under .socket/ — no manifest, no
    // blobs; the ledger's detached entry (written by the vendor step) is the
    // record.
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
        "get --mode vendored must NOT persist blobs (content stays in memory)"
    );

    // The committed copy: patched bytes, no `.cargo-checksum.json`, pristine
    // registry source, ledger written (the capstone's on-disk assertions).
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
    assert_eq!(
        std::fs::read(crate_dir.join("src/lib.rs")).unwrap(),
        orig,
        "registry source must stay pristine"
    );
    assert!(
        proj.join(".socket/vendor/state.json").is_file(),
        "the vendor ledger must be written"
    );

    // `[patch.crates-io]` wiring + the surgical lock detach.
    let config = std::fs::read_to_string(proj.join(".cargo/config.toml"))
        .expect("get --mode vendored must create .cargo/config.toml");
    assert!(
        config.contains("[patch.crates-io]") && config.contains(&copy_rel),
        "config must patch crates-io to the uuid copy path:\n{config}"
    );
    let lock_text = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    let block = package_block(&lock_text, DEP).expect("cfg-if lock entry must survive");
    assert!(
        block.contains(&format!("version = \"{version}\"")),
        "lock entry keeps the version:\n{block}"
    );
    assert!(
        !block.contains("source = ") && !block.contains("checksum = "),
        "lock entry must be detached from the registry (no source/checksum):\n{block}"
    );

    // FRESH-CHECKOUT PROOF: committable files only, EMPTY CARGO_HOME,
    // `--locked --offline` — the consumer references the patched-only
    // symbol, so the build links iff the vendored bytes are what cargo uses.
    std::fs::write(
        proj.join("src/main.rs"),
        "fn main() { println!(\"MARKER:{}\", cfg_if::socket_patched()); }\n",
    )
    .unwrap();
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("Cargo.toml"), fresh.join("Cargo.toml")).unwrap();
    std::fs::copy(proj.join("Cargo.lock"), fresh.join("Cargo.lock")).unwrap();
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
        "fresh-checkout `cargo build --locked --offline` (empty CARGO_HOME) after \
         `get --mode vendored` must succeed.\nstdout:\n{}\nstderr:\n{}",
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
    assert!(
        !fresh_home.join("registry").exists(),
        "fresh CARGO_HOME must not gain a registry/ — the vendored path dep \
         is the sole provider"
    );
    let lock_text = std::fs::read_to_string(fresh.join("Cargo.lock")).unwrap();
    assert_eq!(
        cargo_e2e_matrix::lock_format(&lock_text),
        cargo_e2e_matrix::lock_format(&String::from_utf8_lossy(&lock_before)),
        "the detach must keep the lock format:\n{lock_text}"
    );

    // Manifest-less VEX on the fresh checkout (get wrote a manifest; the
    // steps delete it).
    ManifestlessVendored {
        fresh,
        fresh_home,
        registry_home: cargo_home,
        scratch: tmp.path().join("manifestless"),
        purl,
        patched,
        baseline_lock: lock_before,
    }
    .run_async()
    .await;
}
