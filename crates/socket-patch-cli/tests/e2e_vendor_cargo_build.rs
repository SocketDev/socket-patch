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
//!      `.socket/vendor/cargo/<uuid>/cfg-if-<ver>/` with its `Cargo.toml`
//!      version TAGGED `<ver>+socket.<uuid>`, the `[patch.crates-io]` entry
//!      in the root `Cargo.toml` (no `.cargo/` is created), and the surgical
//!      lock detach (the `[[package]]` entry loses source+checksum and its
//!      version is the tagged one — what `cargo metadata` reports too).
//!   4. COMPILE ORACLE: the consumer's `main.rs` is rewritten to call
//!      `cfg_if::socket_patched()` — it only compiles if the patched bytes
//!      are what cargo links — and `cargo run --locked --offline` prints it,
//!      plus the patched crate's `CARGO_PKG_VERSION` (the tagged version).
//!   5. **Fresh-checkout proof**: copy ONLY the committable files
//!      (Cargo.toml + Cargo.lock + src/ + .socket/) to a new dir
//!      and `cargo build --locked --offline` with an EMPTY CARGO_HOME — and
//!      assert that CARGO_HOME gained no `registry/` (zero crate downloads).
//!   6. **Revert proof**: `vendor --revert` restores Cargo.lock AND
//!      Cargo.toml byte-for-byte and removes `.socket/vendor/`.
//!
//! Also here: MULTI-VERSION (two vendored versions of one crate get
//! distinct `[patch.crates-io]` keys and both compile under `--locked`),
//! LEGACY MIGRATION (a pre-v5 `.cargo/config.toml` wiring is moved into
//! `Cargo.toml` by `repair` and by a `vendor` re-run, and the result still
//! builds; an untagged pre-tag copy + lock is tagged by `repair` and by a
//! re-run), and an OLD-TOOLCHAIN proof (manifest `[patch]` + the detached,
//! tagged lock build the patched copy with no network on cargo 1.41 / 1.56
//! — the local `rust:1.41-slim` / `rust:1.56-slim` docker images, preferred,
//! else installed rustup toolchains 1.36..=1.56 (type-check only) —
//! config-file `[patch]` needs 1.56+; two versions of one crate there need
//! `--offline`; skipped when neither is available, required by the
//! `cargo-old-toolchains` CI leg). Also: a
//! URL-spelled crates.io `[patch]` table is refused, an ancestor-directory
//! config entry cannot silently shadow the vendored copy, and the pre-v5
//! multi-version overwrite is healed by a re-run and by `repair`. TRANSITIVE:
//! a registry crate (`log 0.4.14`) that depends on the patched one follows
//! the tag in every lock format (v1's full-id reference is rewritten) and
//! links the patched copy under `--locked --offline`. REPAIR INVENTORY: a
//! recorded whole-tree inventory carried onto a tagged rebuild is refreshed
//! from the verified rebuild (`vendor_inventory_refreshed`), never deleted.
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

/// The Socket-owned `[patch.crates-io]` key vendoring writes for `uuid`.
fn socket_key(uuid: &str) -> String {
    format!("{DEP}-socket-{}", &uuid.replace('-', "")[..8])
}

/// The manifest entry line vendoring writes for `copy_rel` under `uuid`.
fn socket_entry(uuid: &str, copy_rel: &str) -> String {
    format!(
        "{} = {{ package = \"{DEP}\", path = \"{copy_rel}\" }}",
        socket_key(uuid)
    )
}
/// Appended to the dep's `src/lib.rs`. Doc comment required: cfg-if denies
/// `missing_docs` and path deps get no `--cap-lints allow`.
const PATCH_SUFFIX: &str =
    "\n/// Socket-patch capstone marker (added by the vendored patch).\npub fn socket_patched() -> u32 { 1 }\n\
     /// The version cargo compiled this copy as.\npub fn socket_pkg_version() -> &'static str { env!(\"CARGO_PKG_VERSION\") }\n";

/// The consumer `main.rs` of the compile oracle: the patched-only marker and
/// the patched crate's `CARGO_PKG_VERSION`.
const ORACLE_MAIN: &str =
    "fn main() { println!(\"MARKER:{}:{}\", cfg_if::socket_patched(), cfg_if::socket_pkg_version()); }\n";

/// `version` tagged for `uuid` (the vendored copy's version).
fn tagged(version: &str, uuid: &str) -> String {
    socket_patch_core::vendor::cargo_tag::tag_version(version, uuid)
}

/// The oracle's expected output line for `version` vendored under `uuid`.
fn oracle_line(version: &str, uuid: &str) -> String {
    format!("MARKER:1:{}", tagged(version, uuid))
}

/// Assert `proj` carries the tagged vendored version for `uuid` in both
/// the copy's `Cargo.toml` and the detached `Cargo.lock` entry.
fn assert_tagged(proj: &Path, version: &str, uuid: &str, tag: &str) {
    let copy = proj.join(format!(
        ".socket/vendor/cargo/{uuid}/{DEP}-{version}/Cargo.toml"
    ));
    let text = std::fs::read_to_string(&copy).unwrap();
    assert_eq!(
        socket_patch_core::vendor::cargo_tag::manifest_tag_uuid(&text).as_deref(),
        Some(uuid),
        "{tag}: the copy's version is tagged:\n{text}"
    );
    let lock = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    assert!(
        lock.contains(&format!(
            "name = \"{DEP}\"\nversion = \"{}\"\n",
            tagged(version, uuid)
        )),
        "{tag}: the lock entry carries the tagged version:\n{lock}"
    );
}

/// Undo the tag in `proj` (copy + lock): the untagged shape a pre-tag
/// release committed.
fn untag_project(proj: &Path, version: &str, uuid: &str) {
    let copy = proj.join(format!(
        ".socket/vendor/cargo/{uuid}/{DEP}-{version}/Cargo.toml"
    ));
    let text = std::fs::read_to_string(&copy).unwrap();
    let untagged = socket_patch_core::vendor::cargo_tag::untag_manifest_text(&text)
        .expect("the copy is tagged");
    std::fs::write(&copy, untagged).unwrap();
    let lock = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    std::fs::write(
        proj.join("Cargo.lock"),
        lock.replace(&tagged(version, uuid), version),
    )
    .unwrap();
}

/// The version `cargo metadata --locked --offline` reports for the dep.
fn metadata_version(dir: &Path, cargo_home: &Path) -> String {
    let out = cargo(
        dir,
        &["metadata", "--format-version", "1", "--locked", "--offline"],
        cargo_home,
    );
    assert!(
        out.status.success(),
        "cargo metadata:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    doc["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == DEP)
        .and_then(|p| p["version"].as_str())
        .unwrap_or_default()
        .to_string()
}

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

/// `manifest` without its `[patch.crates-io]` table (the header through the
/// next table header or EOF, plus the blank line before it) — a hand revert
/// of the vendored wiring.
fn strip_patch_table(manifest: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut skipping = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t == "[patch.crates-io]" {
            skipping = true;
            while out.last().is_some_and(|l| l.trim().is_empty()) {
                out.pop();
            }
            continue;
        }
        if skipping && t.starts_with('[') {
            skipping = false;
        }
        if !skipping {
            out.push(line);
        }
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
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
    stage_fixture_with(tmp, tag, "")
}

/// [`stage_fixture`] with `extra_deps` (TOML lines) appended to the
/// consumer's `[dependencies]`.
fn stage_fixture_with(
    tmp: &Path,
    tag: &str,
    extra_deps: &str,
) -> Option<(PathBuf, PathBuf, String, PathBuf)> {
    let proj = tmp.join("proj");
    let cargo_home = tmp.join("cargo-home");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(
        proj.join("Cargo.toml"),
        format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{DEP} = \"1.0\"\n{extra_deps}"
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
        std::fs::copy(fresh.join("Cargo.lock"), revert.join("Cargo.lock")).unwrap();
        std::fs::write(
            revert.join("Cargo.toml"),
            strip_patch_table(&std::fs::read_to_string(fresh.join("Cargo.toml")).unwrap()),
        )
        .unwrap();
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
    let manifest_before = std::fs::read(proj.join("Cargo.toml")).unwrap();

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

    // The `[patch.crates-io]` entry lives in the ROOT MANIFEST (appended
    // after the user's content, which is otherwise byte-identical); no
    // project config is created.
    let manifest = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    assert_eq!(
        manifest,
        format!(
            "{}\n[patch.crates-io]\n{}\n",
            String::from_utf8_lossy(&manifest_before),
            socket_entry(UUID, &copy_rel)
        ),
        "the manifest gains exactly the Socket-owned [patch] entry"
    );
    assert!(
        !proj.join(".cargo").exists(),
        "vendored mode writes no .cargo/config.toml"
    );
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(proj.join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state["entries"][purl.as_str()]["wiring"][0]["file"],
        "Cargo.toml",
        "the ledger records the manifest wiring: {state}"
    );

    // Lock surgery: the entry loses source+checksum (without this, `cargo
    // build --locked` fails closed on the [patch]) and carries the copy's
    // tagged version — the uuid is readable from Cargo.lock alone.
    let lock_text = std::fs::read_to_string(&lock_path).unwrap();
    let block = package_block(&lock_text, DEP).expect("cfg-if lock entry must survive");
    assert!(
        block.contains(&format!("version = \"{}\"", tagged(&version, UUID))),
        "lock entry carries the tagged version:\n{block}"
    );
    assert_tagged(&proj, &version, UUID, "main");
    assert!(
        !block.contains("source = ") && !block.contains("checksum = "),
        "lock entry must be detached from the registry (no source/checksum):\n{block}"
    );
    assert_eq!(
        cargo_e2e_matrix::lock_format(&lock_text),
        cargo_e2e_matrix::lock_format(&String::from_utf8_lossy(&lock_before)),
        "the detach must keep the lock format:\n{lock_text}"
    );

    // COMPILE ORACLE: the consumer references the patched-only symbol, and
    // the patched crate reports its tagged CARGO_PKG_VERSION.
    std::fs::write(proj.join("src/main.rs"), ORACLE_MAIN).unwrap();
    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    assert!(
        run.status.success(),
        "in-place `cargo run --locked --offline` must link the vendored patch.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    );
    assert!(
        String::from_utf8_lossy(&run.stdout).contains(&oracle_line(&version, UUID)),
        "patched symbol must be linked, compiled as the tagged version: {}",
        String::from_utf8_lossy(&run.stdout)
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_text.as_bytes(),
        "cargo keeps the tagged lock byte-stable"
    );

    // FRESH-CHECKOUT PROOF: only the committable files, EMPTY CARGO_HOME,
    // --locked --offline (spike claim 3).
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("Cargo.toml"), fresh.join("Cargo.toml")).unwrap();
    std::fs::copy(&lock_path, fresh.join("Cargo.lock")).unwrap();
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
        String::from_utf8_lossy(&bin.stdout).contains(&oracle_line(&version, UUID)),
        "fresh build must link the PATCHED dep: {}",
        String::from_utf8_lossy(&bin.stdout)
    );
    assert_eq!(
        metadata_version(&fresh, &fresh_home),
        tagged(&version, UUID),
        "cargo metadata reports the tagged version"
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
    // The managed [patch] entry is gone: the manifest is byte-identical to
    // the pre-vendor snapshot.
    assert_eq!(
        std::fs::read(proj.join("Cargo.toml")).unwrap(),
        manifest_before,
        "revert must restore Cargo.toml byte-identical to the pre-vendor snapshot"
    );
    assert!(!proj.join(".cargo").exists());
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

    // `[patch.crates-io]` wiring (root manifest) + the surgical lock detach.
    let manifest = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    assert!(
        manifest.contains("[patch.crates-io]") && manifest.contains(&copy_rel),
        "Cargo.toml must patch crates-io to the uuid copy path:\n{manifest}"
    );
    assert!(!proj.join(".cargo").exists(), "no .cargo/config.toml");
    let lock_text = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    let block = package_block(&lock_text, DEP).expect("cfg-if lock entry must survive");
    assert!(
        block.contains(&format!("version = \"{}\"", tagged(&version, UUID))),
        "lock entry carries the tagged version:\n{block}"
    );
    assert_tagged(&proj, &version, UUID, "get");
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

// ── v5 manifest wiring: multi-version, legacy migration, old toolchains ─

const UUID_OLD: &str = "3c4d5e6f-7081-4b2c-9d3e-123456789abc";
const PATCH_SUFFIX_OLD: &str =
    "\n/// Socket-patch marker for the OLD major (added by the vendored patch).\npub fn socket_patched_old() -> u32 { 2 }\n";

fn vendor_ok(proj: &Path, cargo_home: &Path, tag: &str) -> serde_json::Value {
    let (code, stdout, stderr) = run_socket(
        proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        cargo_home,
    );
    assert_eq!(
        code, 0,
        "{tag}: vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    parse_envelope(&stdout)
}

fn revert_ok(proj: &Path, cargo_home: &Path, tag: &str) {
    let (code, stdout, stderr) = run_socket(
        proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        cargo_home,
    );
    assert_eq!(
        code, 0,
        "{tag}: revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// Copy the committable files (`.cargo/` only when present) to a fresh dir
/// with an empty CARGO_HOME.
fn fresh_checkout(proj: &Path, tmp: &Path, tag: &str) -> (PathBuf, PathBuf) {
    let fresh = tmp.join(format!("fresh-{tag}"));
    std::fs::create_dir_all(&fresh).unwrap();
    for file in ["Cargo.toml", "Cargo.lock"] {
        std::fs::copy(proj.join(file), fresh.join(file)).unwrap();
    }
    for dir in ["src", ".socket", ".cargo"] {
        if proj.join(dir).exists() {
            copy_dir_recursive(&proj.join(dir), &fresh.join(dir));
        }
    }
    let home = tmp.join(format!("fresh-home-{tag}"));
    std::fs::create_dir_all(&home).unwrap();
    (fresh, home)
}

/// The MULTI-VERSION fixture: a consumer locking cfg-if 1.x AND 0.1.x (a
/// renamed dependency), its baseline build, and one staged manifest with a
/// marker patch per version (`UUID` for 1.x, `UUID_OLD` for 0.1.x). `None`
/// when the fixture build is impossible (skip already printed).
struct TwoVersions {
    proj: PathBuf,
    cargo_home: PathBuf,
    new_v: String,
    old_v: String,
    lock_before: Vec<u8>,
    manifest_before: Vec<u8>,
}

fn stage_two_versions(tmp: &Path, tag: &str) -> Option<TwoVersions> {
    let proj = tmp.join("proj");
    let cargo_home = tmp.join("cargo-home");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(
        proj.join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2018\"\n\n\
         [dependencies]\ncfg-if = \"1.0\"\ncfg_if_old = { package = \"cfg-if\", version = \"0.1\" }\n",
    )
    .unwrap();
    std::fs::write(proj.join("src/main.rs"), "fn main() {}\n").unwrap();
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
    // The toolchain's own lock format: the matrix re-encoder models one
    // version per crate (`LockPackage::dependencies` holds names), which a
    // two-version lock is not.
    let lock_before = std::fs::read(proj.join("Cargo.lock")).unwrap();
    let manifest_before = std::fs::read(proj.join("Cargo.toml")).unwrap();
    let locked: Vec<String> = cargo_e2e_matrix::parse_lock(&String::from_utf8_lossy(&lock_before))
        .into_iter()
        .filter(|p| p.name == DEP)
        .map(|p| p.version)
        .collect();
    let new_v = locked
        .iter()
        .find(|v| v.starts_with("1."))
        .expect("cfg-if 1.x locked")
        .clone();
    let old_v = locked
        .iter()
        .find(|v| v.starts_with("0.1."))
        .expect("cfg-if 0.1 locked")
        .clone();

    // One manifest, two patches (one per version), blobs from the real bytes.
    let mut patches = serde_json::Map::new();
    std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
    for (version, uuid, suffix) in [
        (&new_v, UUID, PATCH_SUFFIX),
        (&old_v, UUID_OLD, PATCH_SUFFIX_OLD),
    ] {
        let dir = find_registry_crate(&cargo_home, &format!("{DEP}-{version}"))
            .unwrap_or_else(|| panic!("{DEP}-{version} extracted"));
        let orig = std::fs::read(dir.join("src/lib.rs")).unwrap();
        let patched: Vec<u8> = [orig.as_slice(), suffix.as_bytes()].concat();
        std::fs::write(
            proj.join(".socket/blobs").join(git_sha256(&patched)),
            &patched,
        )
        .unwrap();
        patches.insert(
            format!("pkg:cargo/{DEP}@{version}"),
            serde_json::json!({
                "uuid": uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { "src/lib.rs": {
                    "beforeHash": git_sha256(&orig),
                    "afterHash": git_sha256(&patched),
                }},
                "vulnerabilities": {},
                "description": "multi-version marker patch",
                "license": "MIT",
                "tier": "free",
            }),
        );
    }
    std::fs::write(
        proj.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    )
    .unwrap();

    Some(TwoVersions {
        proj,
        cargo_home,
        new_v,
        old_v,
        lock_before,
        manifest_before,
    })
}

/// The compile oracle for [`TwoVersions`]: a patched-only symbol from EACH
/// version.
const TWO_VERSION_MAIN: &str = "fn main() { println!(\"MARKER:{}:{}\", cfg_if::socket_patched(), cfg_if_old::socket_patched_old()); }\n";

/// MULTI-VERSION: the consumer locks cfg-if 1.x AND 0.1.x (a renamed
/// dependency). Both are vendored: the second version's `[patch.crates-io]`
/// entry takes the Socket-owned `cfg-if-socket-<uuid8>` key with
/// `package = "cfg-if"` (the pre-v5 config wiring keyed by crate name made
/// the second version clobber the first). The compile oracle calls a
/// patched-only symbol from EACH version, in place and on a fresh checkout
/// with an empty CARGO_HOME under `--locked --offline`; the revert restores
/// Cargo.toml and Cargo.lock byte for byte.
#[test]
fn cargo_vendor_two_versions_of_one_crate_locked_build() {
    if !cargo_e2e_matrix::cargo_available("e2e_vendor_cargo_build (multi-version)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some(TwoVersions {
        proj,
        cargo_home,
        new_v,
        old_v,
        lock_before,
        manifest_before,
    }) = stage_two_versions(tmp.path(), "multi-version")
    else {
        return;
    };
    let env = vendor_ok(&proj, &cargo_home, "multi-version");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    let manifest = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    let new_rel = format!(".socket/vendor/cargo/{UUID}/{DEP}-{new_v}");
    let old_rel = format!(".socket/vendor/cargo/{UUID_OLD}/{DEP}-{old_v}");
    let entries: Vec<&str> = manifest
        .lines()
        .skip_while(|l| l.trim() != "[patch.crates-io]")
        .skip(1)
        .collect();
    assert_eq!(entries.len(), 2, "two entries, distinct keys:\n{manifest}");
    for (rel, uuid) in [(&new_rel, UUID), (&old_rel, UUID_OLD)] {
        let line = entries
            .iter()
            .find(|l| l.contains(rel.as_str()))
            .unwrap_or_else(|| panic!("an entry for {rel}:\n{manifest}"));
        assert_eq!(
            *line,
            socket_entry(uuid, rel),
            "each version takes its own Socket-owned key"
        );
    }
    assert!(!proj.join(".cargo").exists());
    // Each version's copy and lock entry carry their own patch's tag.
    assert_tagged(&proj, &new_v, UUID, "multi-version 1.x");
    assert_tagged(&proj, &old_v, UUID_OLD, "multi-version 0.1.x");

    // COMPILE ORACLE: a patched-only symbol from each version.
    std::fs::write(proj.join("src/main.rs"), TWO_VERSION_MAIN).unwrap();
    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    assert!(
        run.status.success() && String::from_utf8_lossy(&run.stdout).contains("MARKER:1:2"),
        "both vendored versions must be linked.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let (fresh, home) = fresh_checkout(&proj, tmp.path(), "multi");
    let build = cargo(&fresh, &["build", "-q", "--locked", "--offline"], &home);
    assert!(
        build.status.success(),
        "fresh multi-version checkout must build:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(!home.join("registry").exists(), "zero crate downloads");
    let out = Command::new(fresh.join("target/debug/consumer"))
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("MARKER:1:2"));

    // Re-vendor is a no-op; revert is byte-identical.
    let lock_wired = std::fs::read(proj.join("Cargo.lock")).unwrap();
    vendor_ok(&proj, &cargo_home, "multi-version rerun");
    assert_eq!(
        std::fs::read_to_string(proj.join("Cargo.toml")).unwrap(),
        manifest
    );
    assert_eq!(std::fs::read(proj.join("Cargo.lock")).unwrap(), lock_wired);
    std::fs::write(proj.join("src/main.rs"), "fn main() {}\n").unwrap();
    revert_ok(&proj, &cargo_home, "multi-version");
    assert_eq!(
        std::fs::read(proj.join("Cargo.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(std::fs::read(proj.join("Cargo.lock")).unwrap(), lock_before);
    assert!(!proj.join(".socket/vendor").exists());
}

/// TRANSITIVE: the patched crate is also a dependency of a REGISTRY crate
/// (`log 0.4.14` requires `cfg-if ^1.0`) — the usual real-world shape. The
/// registry crate's own `dependencies` entry must follow the tag (a v1
/// lock spells it `"cfg-if <v> (registry+…)"`, the form the detach
/// rewrites to `"cfg-if <tagged>"`), so under every
/// `SOCKET_PATCH_CARGO_E2E_LOCK_VERSION` the lock names no untagged
/// cfg-if, `cargo run --locked --offline` links the patched bytes for both
/// dependents, the lock is byte-stable across the build, and the revert
/// restores it byte-identically.
#[test]
fn cargo_vendor_transitive_registry_dependent_locked_build() {
    if !cargo_e2e_matrix::cargo_available("e2e_vendor_cargo_build (transitive)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) =
        stage_fixture_with(tmp.path(), "transitive", "log = \"=0.4.14\"\n")
    else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, "src/lib.rs", &orig, &patched);
    let lock_before = std::fs::read(proj.join("Cargo.lock")).unwrap();
    let manifest_before = std::fs::read(proj.join("Cargo.toml")).unwrap();
    let log_before = package_block(&String::from_utf8_lossy(&lock_before), "log")
        .expect("the fixture locks log");
    assert!(
        log_before.contains(&format!("\"{DEP}")),
        "the registry crate depends on {DEP}:\n{log_before}"
    );

    let env = vendor_ok(&proj, &cargo_home, "transitive");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    assert_tagged(&proj, &version, UUID, "transitive");
    let lock = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    let t = tagged(&version, UUID);
    for stale in [
        format!("\"{DEP} {version}\""),
        format!("\"{DEP} {version} ("),
    ] {
        assert!(
            !lock.contains(&stale),
            "no dependency still names the untagged {DEP} ({stale}):\n{lock}"
        );
    }
    let log_after = package_block(&lock, "log").unwrap();
    if cargo_e2e_matrix::lock_format(&lock) == 1 {
        assert!(
            log_after.contains(&format!("\"{DEP} {t}\"")),
            "v1: the registry crate's full-id reference follows the tag:\n{log_after}"
        );
    } else {
        assert_eq!(
            log_after, log_before,
            "v2+: a plain-name reference needs nothing"
        );
    }

    std::fs::write(proj.join("src/main.rs"), ORACLE_MAIN).unwrap();
    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    assert!(
        run.status.success()
            && String::from_utf8_lossy(&run.stdout).contains(&oracle_line(&version, UUID)),
        "the patched copy must be linked for the direct AND the transitive dependent.\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Cargo.lock")).unwrap(),
        lock,
        "the tagged lock is byte-stable across the locked build"
    );
    assert_eq!(metadata_version(&proj, &cargo_home), t);
    assert_eq!(
        lock.matches(&format!("name = \"{DEP}\"\n")).count(),
        1,
        "one {DEP} in the graph — the tagged copy — so log builds it too:\n{lock}"
    );

    std::fs::write(proj.join("src/main.rs"), "fn main() {}\n").unwrap();
    revert_ok(&proj, &cargo_home, "transitive");
    assert_eq!(std::fs::read(proj.join("Cargo.lock")).unwrap(), lock_before);
    assert_eq!(
        std::fs::read(proj.join("Cargo.toml")).unwrap(),
        manifest_before
    );
    assert!(!proj.join(".socket/vendor").exists());
}

/// Plain-sha256 inventory of every file under `dir` (forward-slashed
/// relative paths) — the ledger's `fileInventory` shape.
fn dir_inventory(dir: &Path) -> serde_json::Map<String, serde_json::Value> {
    fn walk(base: &Path, dir: &Path, out: &mut serde_json::Map<String, serde_json::Value>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let digest = hex::encode(Sha256::digest(std::fs::read(&path).unwrap()));
                out.insert(rel, serde_json::Value::String(digest));
            }
        }
    }
    let mut out = serde_json::Map::new();
    walk(dir, dir, &mut out);
    out
}

/// `repair` over a pre-tag cargo vendor whose ledger carries a whole-tree
/// inventory of ANOTHER build source's tree (an extra file the local
/// rebuild does not reproduce) and whose copy is gone: the rebuild (tagged,
/// with its lock retag) comes back from the backend as a fresh entry with
/// the recorded inventory carried forward, the patched members verify, and
/// the tree mismatch is refreshed from the verified rebuild
/// (`vendor_inventory_refreshed`) — never a deleted rebuild stranding the
/// wiring on a dead dir. The result builds `--locked --offline`.
#[test]
fn cargo_repair_refreshes_a_carried_inventory_over_a_verified_rebuild() {
    if !cargo_e2e_matrix::cargo_available("e2e_vendor_cargo_build (repair-inventory)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) =
        stage_fixture(tmp.path(), "repair-inventory")
    else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let copy_rel = format!(".socket/vendor/cargo/{UUID}/{DEP}-{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, "src/lib.rs", &orig, &patched);
    vendor_ok(&proj, &cargo_home, "repair-inventory");
    untag_project(&proj, &version, UUID);

    let copy = proj.join(&copy_rel);
    std::fs::write(copy.join("PREBUILT_STUB"), "service-only file\n").unwrap();
    let recorded = dir_inventory(&copy);
    let state_path = proj.join(".socket/vendor/state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["entries"][purl.as_str()]["artifact"]["fileInventory"] =
        serde_json::Value::Object(recorded.clone());
    std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
    std::fs::remove_dir_all(&copy).unwrap();

    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "repair",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &cargo_home,
    );
    assert_eq!(
        code, 0,
        "repair failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("vendor_inventory_refreshed"), "{stdout}");
    assert!(stdout.contains("cargo_version_tagged"), "{stdout}");
    assert_tagged(&proj, &version, UUID, "repair-inventory");
    assert_eq!(std::fs::read(copy.join("src/lib.rs")).unwrap(), patched);
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    let inventory = state["entries"][purl.as_str()]["artifact"]["fileInventory"]
        .as_object()
        .unwrap_or_else(|| panic!("the refreshed inventory is persisted: {state}"));
    assert!(!inventory.contains_key("PREBUILT_STUB"), "{inventory:?}");
    assert_eq!(
        inventory,
        &dir_inventory(&copy),
        "the verified rebuild's tree"
    );

    std::fs::write(proj.join("src/main.rs"), ORACLE_MAIN).unwrap();
    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    assert!(
        String::from_utf8_lossy(&run.stdout).contains(&oracle_line(&version, UUID)),
        "the repaired copy builds: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// Turn the v5 wiring of `proj` into what a pre-v5 release wrote: the
/// `[patch.crates-io]` entry in `.cargo/config.toml` (Cargo.toml without
/// it), the copy and lock entry untagged, and the ledger's patch-entry
/// record naming the config.
fn downgrade_to_legacy_wiring(proj: &Path, purl: &str, copy_rel: &str) {
    let version = purl.rsplit('@').next().unwrap();
    untag_project(proj, version, UUID);
    let manifest = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    std::fs::write(proj.join("Cargo.toml"), strip_patch_table(&manifest)).unwrap();
    std::fs::create_dir_all(proj.join(".cargo")).unwrap();
    std::fs::write(
        proj.join(".cargo/config.toml"),
        format!("[patch.crates-io]\n{DEP} = {{ path = \"{copy_rel}\" }}\n"),
    )
    .unwrap();
    let state_path = proj.join(".socket/vendor/state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    let wiring = state["entries"][purl]["wiring"].as_array_mut().unwrap();
    for w in wiring.iter_mut() {
        if w["kind"] == "cargo_patch_entry" {
            w["file"] = ".cargo/config.toml".into();
        }
    }
    std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
}

fn assert_migrated(proj: &Path, purl: &str, copy_rel: &str, tag: &str) {
    let manifest = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    assert!(
        manifest.contains(&format!(
            "[patch.crates-io]\n{}",
            socket_entry(UUID, copy_rel)
        )),
        "{tag}: the entry moved into Cargo.toml:\n{manifest}"
    );
    assert!(
        !proj.join(".cargo").exists(),
        "{tag}: the socket-created legacy config (and .cargo/) are cleaned"
    );
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(proj.join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    let entry = &state["entries"][purl];
    let files: Vec<&str> = entry["wiring"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["file"].as_str().unwrap())
        .collect();
    assert_eq!(files, vec!["Cargo.toml", "Cargo.lock"], "{tag}: {entry}");
    assert_eq!(
        entry["lock"]["source"], "registry+https://github.com/rust-lang/crates.io-index",
        "{tag}: the unrecoverable lock originals survive the migration: {entry}"
    );
    let version = purl.rsplit('@').next().unwrap();
    assert_tagged(proj, version, UUID, tag);
}

/// LEGACY MIGRATION: a project vendored by a pre-v5 release (the
/// `[patch.crates-io]` entry in `.cargo/config.toml`, untagged copy and
/// lock) still builds, and both `repair` and a plain `vendor` re-run move
/// the wiring into Cargo.toml and tag the copy + lock — ledger updated,
/// lock originals kept — after which the project still builds `--locked
/// --offline` on a fresh checkout and the revert restores the pristine
/// files. The untagged MANIFEST shape (an earlier v5 build) is tagged by
/// `repair` too.
#[test]
fn cargo_legacy_config_wiring_migrates_to_the_manifest() {
    if !cargo_e2e_matrix::cargo_available("e2e_vendor_cargo_build (legacy-migration)") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) =
        stage_fixture(tmp.path(), "legacy-migration")
    else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let copy_rel = format!(".socket/vendor/cargo/{UUID}/{DEP}-{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, "src/lib.rs", &orig, &patched);
    let lock_before = std::fs::read(proj.join("Cargo.lock")).unwrap();
    let manifest_before = std::fs::read(proj.join("Cargo.toml")).unwrap();
    vendor_ok(&proj, &cargo_home, "legacy-migration");
    std::fs::write(proj.join("src/main.rs"), ORACLE_MAIN).unwrap();

    // The pre-v5 shape builds (config `[patch]`, cargo 1.56+).
    downgrade_to_legacy_wiring(&proj, &purl, &copy_rel);
    assert_eq!(
        std::fs::read(proj.join("Cargo.toml")).unwrap(),
        manifest_before
    );
    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    assert!(
        String::from_utf8_lossy(&run.stdout).contains(&format!("MARKER:1:{version}\n")),
        "the legacy (untagged) wiring builds: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    // (1) `repair` migrates.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "repair",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &cargo_home,
    );
    assert_eq!(
        code, 0,
        "repair failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("cargo_wiring_migrated"), "{stdout}");
    assert!(stdout.contains("cargo_version_tagged"), "{stdout}");
    assert_migrated(&proj, &purl, &copy_rel, "repair");

    // (2) A plain `vendor` re-run migrates.
    downgrade_to_legacy_wiring(&proj, &purl, &copy_rel);
    let env = vendor_ok(&proj, &cargo_home, "legacy re-run");
    assert!(env.to_string().contains("cargo_wiring_migrated"), "{env}");
    assert!(env.to_string().contains("cargo_version_tagged"), "{env}");
    assert_migrated(&proj, &purl, &copy_rel, "vendor re-run");

    // (3) The untagged manifest shape: `repair` tags it in place.
    untag_project(&proj, &version, UUID);
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "repair",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &cargo_home,
    );
    assert_eq!(
        code, 0,
        "repair (tag) failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("cargo_version_tagged"), "{stdout}");
    assert!(!stdout.contains("cargo_wiring_migrated"), "{stdout}");
    assert_migrated(&proj, &purl, &copy_rel, "repair (tag only)");

    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    assert!(
        String::from_utf8_lossy(&run.stdout).contains(&oracle_line(&version, UUID)),
        "the migrated wiring builds the tagged copy: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let (fresh, home) = fresh_checkout(&proj, tmp.path(), "migrated");
    let build = cargo(&fresh, &["build", "-q", "--locked", "--offline"], &home);
    assert!(
        build.status.success(),
        "fresh migrated checkout must build:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(!home.join("registry").exists());

    // A legacy ledger reverts cleanly too (config + manifest both cleaned).
    downgrade_to_legacy_wiring(&proj, &purl, &copy_rel);
    std::fs::write(
        proj.join("src/main.rs"),
        "fn main() { println!(\"baseline\"); }\n",
    )
    .unwrap();
    revert_ok(&proj, &cargo_home, "legacy revert");
    assert_eq!(
        std::fs::read(proj.join("Cargo.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(std::fs::read(proj.join("Cargo.lock")).unwrap(), lock_before);
    assert!(!proj.join(".cargo").exists());
    assert!(!proj.join(".socket/vendor").exists());
}

// ── build-metadata versions (the encoded purl the API serves) ─────────

/// A dep-free crates.io crate whose version carries semver BUILD METADATA.
const META_DEP: &str = "wasi";
const META_VERSION: &str = "0.11.0+wasi-snapshot-preview1";

/// BUILD METADATA: the patches API serves canonical purls, so this crate's
/// version arrives percent-encoded (`0.11.0%2Bwasi-snapshot-preview1`).
/// REGRESSION: the vendored backend compared that raw spelling against
/// Cargo.lock's `0.11.0+wasi-snapshot-preview1` and refused
/// (`vendor_fetched_missing` then `locked_version_mismatch`), so no crate
/// with build metadata — `wasi` is in most Rust dependency graphs — could
/// ever be vendored. Proves the whole committable shape for one: the copy
/// dir keeps the DECODED version, its manifest is tagged
/// `<version>.socket.<uuid>` (the tag appends to existing metadata), the
/// lock entry is detached at the tagged version, real cargo builds and runs
/// the patched bytes under `--locked --offline`, and `--revert` restores
/// both files byte-for-byte.
#[test]
fn cargo_vendor_build_metadata_version_from_encoded_purl() {
    const SUITE: &str = "e2e_vendor_cargo_build (build-metadata)";
    if !cargo_e2e_matrix::cargo_available(SUITE) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    // A consumer whose ONLY dependency is the build-metadata crate, so the
    // fresh-checkout build below has no unvendored registry dep to fetch.
    let proj = tmp.path().join("proj");
    let cargo_home = tmp.path().join("cargo-home");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(
        proj.join("Cargo.toml"),
        format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{META_DEP} = \"={META_VERSION}\"\n"
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
            SUITE,
            &format!(
                "baseline `cargo build` failed (crates.io unreachable?):\n{}",
                String::from_utf8_lossy(&build.stderr)
            ),
        );
        return;
    }
    cargo_e2e_matrix::apply_lock_version(&proj);
    let lock_text = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    let version = locked_version(&lock_text, META_DEP)
        .unwrap_or_else(|| panic!("Cargo.lock must lock {META_DEP}:\n{lock_text}"));
    assert_eq!(
        version, META_VERSION,
        "the fixture pins the build-metadata version"
    );
    let crate_dir = find_registry_crate(&cargo_home, &format!("{META_DEP}-{version}"))
        .unwrap_or_else(|| panic!("{META_DEP}-{version} must be extracted under registry/src"));

    // EXACTLY what the API serves: the version percent-encoded.
    let purl = format!("pkg:cargo/{META_DEP}@{}", version.replace('+', "%2B"));
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let suffix = b"\n/// Socket-patch build-metadata marker.\npub fn socket_patched() -> u32 { 1 }\n\
                   /// The version cargo compiled this copy as.\npub fn socket_pkg_version() -> &'static str { env!(\"CARGO_PKG_VERSION\") }\n";
    let patched: Vec<u8> = [orig.as_slice(), suffix.as_slice()].concat();
    stage_patch(&proj, &purl, "src/lib.rs", &orig, &patched);

    let manifest_before = std::fs::read(proj.join("Cargo.toml")).unwrap();
    let lock_before = std::fs::read(proj.join("Cargo.lock")).unwrap();

    let env = vendor_ok(&proj, &cargo_home, "build-metadata");
    assert_eq!(
        env["summary"]["failed"], 0,
        "no refusal for a build-metadata version: {env}"
    );

    // The copy dir and the ledger key off the DECODED version.
    let copy_rel = format!(".socket/vendor/cargo/{UUID}/{META_DEP}-{version}");
    let copy_manifest = std::fs::read_to_string(proj.join(&copy_rel).join("Cargo.toml")).unwrap();
    assert_eq!(
        socket_patch_core::vendor::cargo_tag::manifest_tag_uuid(&copy_manifest).as_deref(),
        Some(UUID),
        "the copy's version is tagged:\n{copy_manifest}"
    );
    let tagged_version = socket_patch_core::vendor::cargo_tag::tag_version(&version, UUID);
    assert_eq!(
        tagged_version,
        format!("{version}.socket.{UUID}"),
        "the tag appends to the existing build metadata"
    );
    let lock_after = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    assert!(
        lock_after.contains(&format!(
            "name = \"{META_DEP}\"\nversion = \"{tagged_version}\"\n"
        )),
        "the lock entry carries the tagged version:\n{lock_after}"
    );
    let manifest_after = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    assert!(
        manifest_after.contains(&format!(
            "{META_DEP}-socket-{} = {{ package = \"{META_DEP}\", path = \"{copy_rel}\" }}",
            &UUID.replace('-', "")[..8]
        )),
        "the [patch.crates-io] entry pins the copy:\n{manifest_after}"
    );

    // COMPILE ORACLE: only the patched bytes have `socket_patched`.
    std::fs::write(
        proj.join("src/main.rs"),
        format!(
            "fn main() {{ println!(\"MARKER:{{}}:{{}}\", {META_DEP}::socket_patched(), {META_DEP}::socket_pkg_version()); }}\n"
        ),
    )
    .unwrap();
    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    assert!(
        String::from_utf8_lossy(&run.stdout).contains(&format!("MARKER:1:{tagged_version}")),
        "the patched copy builds and runs as the tagged version:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    // Fresh checkout: committable, and nothing is fetched.
    let (fresh, home) = fresh_checkout(&proj, tmp.path(), "build-metadata");
    let build = cargo(&fresh, &["build", "-q", "--locked", "--offline"], &home);
    assert!(
        build.status.success(),
        "the fresh checkout must build:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(!home.join("registry").exists(), "zero crate downloads");

    // Revert is byte-identical.
    std::fs::write(
        proj.join("src/main.rs"),
        "fn main() { println!(\"baseline\"); }\n",
    )
    .unwrap();
    revert_ok(&proj, &cargo_home, "build-metadata");
    assert_eq!(
        std::fs::read(proj.join("Cargo.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(std::fs::read(proj.join("Cargo.lock")).unwrap(), lock_before);
    assert!(!proj.join(".socket/vendor").exists());
}

/// Set to `1` by the CI leg that provides old cargos: then finding none
/// is a failure, not a skip (the regular matrix legs set
/// `SOCKET_PATCH_CARGO_E2E_REQUIRED` but provide no old cargo).
const OLD_TOOLCHAINS_REQUIRED_ENV: &str = "SOCKET_PATCH_CARGO_OLD_TOOLCHAINS_REQUIRED";

/// The official images of the old cargos under test, used when present
/// locally (the test never pulls; the CI leg does).
const OLD_CARGO_IMAGES: [(&str, u32); 2] = [("rust:1.41-slim", 41), ("rust:1.56-slim", 56)];

/// One old cargo under test.
#[derive(Clone, Debug)]
enum OldCargo {
    /// A local docker image: runs with `--network none`, and BUILDS (and
    /// runs) the consumer — Linux links fine.
    Docker { image: String, minor: u32 },
    /// A rustup toolchain on the host: type-check only (old rustc cannot
    /// link against a current Xcode on Apple Silicon).
    Rustup { toolchain: String, minor: u32 },
}

impl OldCargo {
    fn minor(&self) -> u32 {
        match self {
            Self::Docker { minor, .. } | Self::Rustup { minor, .. } => *minor,
        }
    }

    fn name(&self) -> String {
        match self {
            Self::Docker { image, .. } => format!("docker {image}"),
            Self::Rustup { toolchain, .. } => format!("rustup {toolchain}"),
        }
    }

    /// The lock format this cargo writes (v3 from 1.53, v2 from 1.41).
    fn lock_version(&self) -> u8 {
        match self.minor() {
            m if m >= 53 => 3,
            m if m >= 41 => 2,
            _ => 1,
        }
    }
}

fn docker_image_present(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", image])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Installed rustup toolchains 1.36 (`--offline`) through 1.56 (the floor of
/// config-file `[patch]`): `(full toolchain name, minor)`.
fn old_toolchains() -> Vec<(String, u32)> {
    let Ok(out) = Command::new("rustup").args(["toolchain", "list"]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let name = line.split_whitespace().next()?.to_string();
            let minor: u32 = name
                .strip_prefix("1.")?
                .split(['.', '-'])
                .next()?
                .parse()
                .ok()?;
            (36..=56).contains(&minor).then_some((name, minor))
        })
        .collect()
}

/// The old cargos available here: the local docker images first
/// (preferred), then any installed rustup toolchain 1.36..=1.56 for a minor
/// no image covers.
fn old_cargos() -> Vec<OldCargo> {
    let mut out: Vec<OldCargo> = OLD_CARGO_IMAGES
        .iter()
        .filter(|(image, _)| docker_image_present(image))
        .map(|(image, minor)| OldCargo::Docker {
            image: image.to_string(),
            minor: *minor,
        })
        .collect();
    for (toolchain, minor) in old_toolchains() {
        if !out.iter().any(|c| c.minor() == minor) {
            out.push(OldCargo::Rustup { toolchain, minor });
        }
    }
    out
}

/// The old cargos, or `None` (skip printed) when none is available — a
/// failure under [`OLD_TOOLCHAINS_REQUIRED_ENV`].
fn old_cargos_or_skip(suite: &str) -> Option<Vec<OldCargo>> {
    let cargos = old_cargos();
    if cargos.is_empty() {
        assert!(
            std::env::var(OLD_TOOLCHAINS_REQUIRED_ENV).as_deref() != Ok("1"),
            "{suite}: no local rust:1.41-slim / rust:1.56-slim docker image and no rustup \
             toolchain 1.36..=1.56, and {OLD_TOOLCHAINS_REQUIRED_ENV}=1 is set"
        );
        println!(
            "SKIP {suite}: no local rust:1.41-slim / rust:1.56-slim docker image and no \
             rustup toolchain 1.36..=1.56"
        );
        return None;
    }
    Some(cargos)
}

/// What one old-cargo run produced.
struct OldRun {
    out: Output,
    /// The private CARGO_HOME gained a `registry/` (something was fetched).
    fetched: bool,
}

/// Run `cargo <build|check> -q --locked` (plus `extra`) on the fresh
/// checkout `dir` with an empty private CARGO_HOME and NO network: a docker
/// image runs `--network none` and builds, then runs, the consumer (its
/// stdout is the oracle's); a rustup toolchain type-checks with the network
/// pointed at a dead proxy.
fn old_cargo_run(cargo: &OldCargo, dir: &Path, extra: &[&str]) -> OldRun {
    let home_rel = ".old-cargo-home";
    let out = match cargo {
        OldCargo::Docker { image, .. } => {
            let id = |flag: &str| {
                Command::new("id")
                    .arg(flag)
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default()
            };
            let script = format!(
                "cargo build -q --locked {} && ./target/debug/consumer",
                extra.join(" ")
            );
            Command::new("docker")
                .args(["run", "--rm", "--network", "none"])
                .args(["-u", &format!("{}:{}", id("-u"), id("-g"))])
                .args(["-v", &format!("{}:/w", dir.display()), "-w", "/w"])
                .args(["-e", &format!("CARGO_HOME=/w/{home_rel}"), "-e", "HOME=/w"])
                .arg(image)
                .args(["sh", "-c", &script])
                .output()
                .expect("run docker")
        }
        OldCargo::Rustup { toolchain, .. } => Command::new("cargo")
            .args(["check", "-q", "--locked"])
            .args(extra)
            .current_dir(dir)
            .env("CARGO_HOME", dir.join(home_rel))
            .env("RUSTUP_TOOLCHAIN", toolchain)
            .env("CARGO_HTTP_PROXY", "http://127.0.0.1:9")
            .env("CARGO_NET_RETRY", "0")
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .expect("run old cargo"),
    };
    OldRun {
        out,
        fetched: dir.join(home_rel).join("registry").exists(),
    }
}

/// A current-cargo (v4) registry-only lock rewritten in the format `minor`
/// reads: for registry sources v3 differs from v4 only in the version
/// marker, and v2 is v3 without it.
fn lock_for_minor(lock: &str, minor: u32) -> String {
    let marker = if minor >= 53 { "version = 3\n" } else { "" };
    lock.replacen("version = 4\n", marker, 1)
}

/// OLD TOOLCHAIN: the committed v5 wiring (manifest `[patch]` under the
/// Socket-owned renamed key + the detached, TAGGED lock, in the lock format
/// that cargo writes) builds the patched copy on cargo 1.41 and 1.56 —
/// below the 1.56 floor of config-file `[patch]` — with an empty
/// CARGO_HOME, NO network and NO `--offline`, fetching nothing; in docker
/// the consumer runs and prints the patched marker and the tagged
/// `CARGO_PKG_VERSION`. Skips when no old cargo is available (never pulls
/// or installs one); the `cargo-old-toolchains` CI leg pulls the images and
/// requires it.
#[test]
fn cargo_vendored_manifest_patch_builds_on_old_toolchains() {
    const SUITE: &str = "e2e_vendor_cargo_build (old-toolchain)";
    let Some(cargos) = old_cargos_or_skip(SUITE) else {
        return;
    };
    if !cargo_e2e_matrix::cargo_available(SUITE) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path(), "old-toolchain")
    else {
        return;
    };
    // Edition 2021 needs cargo 1.56.
    let manifest = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    std::fs::write(
        proj.join("Cargo.toml"),
        manifest.replace("edition = \"2021\"", "edition = \"2018\""),
    )
    .unwrap();
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, "src/lib.rs", &orig, &patched);
    vendor_ok(&proj, &cargo_home, "old-toolchain");
    assert!(
        std::fs::read_to_string(proj.join("Cargo.toml"))
            .unwrap()
            .contains(&format!("{} = {{ package = ", socket_key(UUID))),
        "the renamed Socket-owned key is what old cargo must accept"
    );
    assert_tagged(&proj, &version, UUID, "old-toolchain");
    std::fs::write(proj.join("src/main.rs"), ORACLE_MAIN).unwrap();
    let pkgs =
        cargo_e2e_matrix::parse_lock(&std::fs::read_to_string(proj.join("Cargo.lock")).unwrap());
    for old in cargos {
        let name = old.name();
        let (fresh, _) = fresh_checkout(&proj, tmp.path(), &format!("old-{}", old.minor()));
        let lock_version = old.lock_version();
        std::fs::write(
            fresh.join("Cargo.lock"),
            cargo_e2e_matrix::write_lock(&pkgs, lock_version),
        )
        .unwrap();
        let run = old_cargo_run(&old, &fresh, &[]);
        assert!(
            run.out.status.success(),
            "{name}: manifest [patch] + detached tagged lock v{lock_version} must build the \
             patched copy with no network:\n{}",
            String::from_utf8_lossy(&run.out.stderr)
        );
        assert!(
            !run.fetched,
            "{name}: nothing is fetched (not even the registry index)"
        );
        if matches!(old, OldCargo::Docker { .. }) {
            assert!(
                String::from_utf8_lossy(&run.out.stdout).contains(&oracle_line(&version, UUID)),
                "{name}: the patched copy runs as the tagged version: {}",
                String::from_utf8_lossy(&run.out.stdout)
            );
        }
        println!("old-toolchain {name}: OK (lock v{lock_version})");
        let _ = std::fs::remove_dir_all(&fresh);
    }
}

/// OLD TOOLCHAIN, TWO VERSIONS of one crate: older cargo loads the
/// crates.io index to tell two same-named `[patch]` entries apart. Every
/// clause of the documented constraint is ASSERTED here, in both
/// directions, because both arms run with no network (docker `--network
/// none`, rustup pointed at a dead proxy):
///
/// * without `--offline` the build MUST fail, and fail on the unreachable
///   index — the negative control for "pass `--offline`";
/// * cargo 1.56 then builds under `--offline` from an EMPTY CARGO_HOME;
/// * older cargo (1.41) MUST first fail even under `--offline` (no registry
///   cache to read), and the documented remedy — a populated crates.io
///   index in `$CARGO_HOME` — must then build (and run) both patched
///   copies with no network. That step is unconditional below 1.56, so a
///   cargo that stops needing it fails this test instead of silently
///   skipping the remedy.
///
/// Current stable needs neither — see
/// `cargo_vendor_two_versions_of_one_crate_locked_build`.
#[test]
fn cargo_vendored_two_versions_on_old_toolchains_need_offline() {
    const SUITE: &str = "e2e_vendor_cargo_build (old-toolchain multi-version)";
    let Some(cargos) = old_cargos_or_skip(SUITE) else {
        return;
    };
    if !cargo_e2e_matrix::cargo_available(SUITE) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some(fx) = stage_two_versions(tmp.path(), "old-toolchain multi-version") else {
        return;
    };
    let env = vendor_ok(&fx.proj, &fx.cargo_home, "old-toolchain multi-version");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    std::fs::write(fx.proj.join("src/main.rs"), TWO_VERSION_MAIN).unwrap();
    let lock = std::fs::read_to_string(fx.proj.join("Cargo.lock")).unwrap();
    if !lock.contains("version = 4\n") {
        let _ = cargo_e2e_matrix::skip(SUITE, "the baseline lock is not v4 (pinned toolchain)");
        return;
    }
    for old in cargos {
        let name = old.name();
        let (fresh, _) = fresh_checkout(&fx.proj, tmp.path(), &format!("mv-{}", old.minor()));
        std::fs::write(fresh.join("Cargo.lock"), lock_for_minor(&lock, old.minor())).unwrap();
        // What an old cargo says when it must load the crates.io index and
        // cannot reach it: 1.56 fails to update the registry, 1.41 fails to
        // resolve the index host. Both name the index or its host, which is
        // what distinguishes this from a wiring failure.
        const INDEX_UNREACHABLE: [&str; 3] = ["crates.io-index", "crates-io", "github.com"];
        let online = old_cargo_run(&old, &fresh, &[]);
        let online_stderr = String::from_utf8_lossy(&online.out.stderr).into_owned();
        assert!(
            !online.out.status.success(),
            "{name}: with no network and no --offline the two-version wiring must NOT \
             build — the constraint the docs state:\n{online_stderr}"
        );
        assert!(
            INDEX_UNREACHABLE.iter().any(|m| online_stderr.contains(m)),
            "{name}: it must fail on the unreachable crates.io index, not on the \
             wiring:\n{online_stderr}"
        );
        println!("old-toolchain multi-version {name} without --offline: needs the index");
        let mut run = old_cargo_run(&old, &fresh, &["--offline"]);
        if old.minor() < 56 {
            let stderr = String::from_utf8_lossy(&run.out.stderr).into_owned();
            assert!(
                !run.out.status.success(),
                "{name}: below 1.56 an EMPTY CARGO_HOME cannot tell the two [patch] \
                 entries apart offline — the reason the index remedy is documented:\n\
                 {stderr}"
            );
            assert!(
                stderr.contains("unable to fetch registry") && stderr.contains("in offline mode"),
                "{name}: the only accepted failure below 1.56 is the missing registry \
                 index:\n{stderr}"
            );
            println!("old-toolchain multi-version {name}: needs a registry index (documented)");
            seed_old_crates_io_index(&fresh.join(".old-cargo-home"), &[&fx.new_v, &fx.old_v]);
            run = old_cargo_run(&old, &fresh, &["--offline"]);
        }
        assert!(
            run.out.status.success(),
            "{name}: two vendored versions must build under --offline:\n{}",
            String::from_utf8_lossy(&run.out.stderr)
        );
        if matches!(old, OldCargo::Docker { .. }) {
            assert!(
                String::from_utf8_lossy(&run.out.stdout).contains("MARKER:1:2"),
                "{name}: both patched copies run: {}",
                String::from_utf8_lossy(&run.out.stdout)
            );
        }
        let _ = std::fs::remove_dir_all(&fresh);
    }
}

/// The documented remedy for two vendored versions on cargo older than
/// 1.56: a populated crates.io index in `$CARGO_HOME`. Writes the minimal
/// one an old cargo reads offline — the git index at the pre-1.85
/// `registry/index/github.com-1ecc6299db9ec823` path (`origin/HEAD` names
/// the tree cargo loads), listing `versions` of the patched crate. No
/// `.crate` is cached: every listed version is patched to a path copy, so
/// nothing is downloaded.
fn seed_old_crates_io_index(cargo_home: &Path, versions: &[&str]) {
    let index = cargo_home.join("registry/index/github.com-1ecc6299db9ec823");
    let file = index.join(&DEP[..2]).join(&DEP[2..4]).join(DEP);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(
        index.join("config.json"),
        "{\"dl\":\"https://crates.io/api/v1/crates\",\"api\":\"https://crates.io\"}\n",
    )
    .unwrap();
    let lines: String = versions
        .iter()
        .map(|v| {
            format!(
                "{{\"name\":\"{DEP}\",\"vers\":\"{v}\",\"deps\":[],\"cksum\":\"{}\",\
                 \"features\":{{}},\"yanked\":false}}\n",
                "0".repeat(64)
            )
        })
        .collect();
    std::fs::write(&file, lines).unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=socket-patch-e2e",
                "-c",
                "user.email=e2e@invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .current_dir(&index)
            .output()
            .expect("run git");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&["init", "-q", "."]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "index"]);
    git(&["update-ref", "refs/remotes/origin/HEAD", "HEAD"]);
}

/// A root manifest that spells crates.io by URL in `[patch]` (cargo lets
/// that table replace `[patch.crates-io]` wholesale) is refused with no
/// write, so the project keeps building `--locked --offline` exactly as
/// before — never a "success" whose wiring cargo silently ignores.
#[test]
fn cargo_url_spelled_crates_io_patch_table_is_refused() {
    const SUITE: &str = "e2e_vendor_cargo_build (url-patch-table)";
    if !cargo_e2e_matrix::cargo_available(SUITE) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path(), "url-patch-table")
    else {
        return;
    };
    // A user's same-version fork of cfg-if under the URL spelling.
    copy_dir_recursive(&crate_dir, &proj.join("fork-cfg-if"));
    let manifest = format!(
        "{}\n[patch.\"https://github.com/rust-lang/crates.io-index\"]\n{DEP} = {{ path = \"fork-cfg-if\" }}\n",
        std::fs::read_to_string(proj.join("Cargo.toml")).unwrap()
    );
    std::fs::write(proj.join("Cargo.toml"), &manifest).unwrap();
    let relock = cargo(&proj, &["build", "-q", "--offline"], &cargo_home);
    assert!(
        relock.status.success(),
        "{}",
        String::from_utf8_lossy(&relock.stderr)
    );
    let manifest = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    let lock = std::fs::read(proj.join("Cargo.lock")).unwrap();
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
    assert!(
        stdout.contains("cargo_manifest_patch_source_alias"),
        "exit {code}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Cargo.toml")).unwrap(),
        manifest
    );
    assert_eq!(std::fs::read(proj.join("Cargo.lock")).unwrap(), lock);
    assert!(!proj.join(format!(".socket/vendor/cargo/{UUID}")).exists());
    let build = cargo(
        &proj,
        &["build", "-q", "--locked", "--offline"],
        &cargo_home,
    );
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
}

/// Cargo lets a config-file `[patch]` item — from ANY config it merges,
/// including an ancestor directory's — replace the manifest item with the
/// same key regardless of version. The Socket-owned key keeps a user's
/// crate-named entry added after vendoring from silently building their
/// unpatched copy: cargo fails loudly on the duplicate patch instead.
#[test]
fn cargo_ancestor_config_patch_cannot_silently_shadow_the_vendored_copy() {
    const SUITE: &str = "e2e_vendor_cargo_build (ancestor-config)";
    if !cargo_e2e_matrix::cargo_available(SUITE) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path(), "ancestor-config")
    else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, "src/lib.rs", &orig, &patched);
    vendor_ok(&proj, &cargo_home, "ancestor-config");
    std::fs::write(
        proj.join("src/main.rs"),
        "fn main() { println!(\"MARKER:{}\", cfg_if::socket_patched()); }\n",
    )
    .unwrap();
    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    assert!(String::from_utf8_lossy(&run.stdout).contains("MARKER:1"));

    // A monorepo-level config adds the user's same-version, unpatched fork
    // under the bare crate name.
    let fork = tmp.path().join(format!("forks/{DEP}-{version}"));
    copy_dir_recursive(&crate_dir, &fork);
    std::fs::create_dir_all(tmp.path().join(".cargo")).unwrap();
    std::fs::write(
        tmp.path().join(".cargo/config.toml"),
        format!("[patch.crates-io]\n{DEP} = {{ path = \"forks/{DEP}-{version}\" }}\n"),
    )
    .unwrap();
    let run = cargo(&proj, &["run", "-q", "--locked", "--offline"], &cargo_home);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        !run.status.success() && !stderr.contains("socket_patched"),
        "the user's fork must never silently replace the vendored copy \
         (a loud duplicate-patch error is expected).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // A re-run refuses rather than wiring over the conflict.
    let (_, out, _) = run_socket(
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
    assert!(out.contains("user_authored_patch_entry"), "{out}");
}

/// PRE-V5 OVERWRITE: a pre-v5 release keyed the config `[patch]` by crate
/// name, so vendoring a second version repointed the first version's entry
/// and left its lock entry detached with no wiring (every `--locked` build
/// broken). Both a v5 `vendor` re-run and `repair` heal that layout into
/// two manifest entries that build `--locked --offline`.
#[test]
fn cargo_pre_v5_multi_version_overwrite_is_healed() {
    const SUITE: &str = "e2e_vendor_cargo_build (pre-v5 overwrite)";
    if !cargo_e2e_matrix::cargo_available(SUITE) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some(fx) = stage_two_versions(tmp.path(), "pre-v5 overwrite") else {
        return;
    };
    let proj = &fx.proj;
    let env = vendor_ok(proj, &fx.cargo_home, "pre-v5 overwrite");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    std::fs::write(proj.join("src/main.rs"), TWO_VERSION_MAIN).unwrap();
    let old_rel = format!(".socket/vendor/cargo/{UUID_OLD}/{DEP}-{}", fx.old_v);
    let clobber = || {
        let manifest = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
        std::fs::write(proj.join("Cargo.toml"), strip_patch_table(&manifest)).unwrap();
        std::fs::create_dir_all(proj.join(".cargo")).unwrap();
        std::fs::write(
            proj.join(".cargo/config.toml"),
            format!("[patch.crates-io]\n{DEP} = {{ path = \"{old_rel}\" }}\n"),
        )
        .unwrap();
        let state_path = proj.join(".socket/vendor/state.json");
        let mut state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
        for (_, entry) in state["entries"].as_object_mut().unwrap() {
            for w in entry["wiring"].as_array_mut().unwrap() {
                if w["kind"] == "cargo_patch_entry" {
                    w["file"] = ".cargo/config.toml".into();
                    w["key"] = DEP.into();
                }
            }
        }
        std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
        let broken = cargo(
            proj,
            &["build", "-q", "--locked", "--offline"],
            &fx.cargo_home,
        );
        assert!(!broken.status.success(), "the clobbered layout is broken");
    };
    let healed = |tag: &str| {
        let manifest = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
        assert_eq!(
            manifest.matches(&format!("{DEP}-socket-")).count(),
            2,
            "{tag}: both versions wired:\n{manifest}"
        );
        assert!(!proj.join(".cargo").exists(), "{tag}");
        let run = cargo(
            proj,
            &["run", "-q", "--locked", "--offline"],
            &fx.cargo_home,
        );
        assert!(
            String::from_utf8_lossy(&run.stdout).contains("MARKER:1:2"),
            "{tag}: both patched versions build:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
    };

    clobber();
    vendor_ok(proj, &fx.cargo_home, "pre-v5 overwrite re-run");
    healed("vendor re-run");

    clobber();
    let (code, stdout, stderr) = run_socket(
        proj,
        &[
            "repair",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &fx.cargo_home,
    );
    assert_eq!(
        code, 0,
        "repair failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    healed("repair");

    std::fs::write(proj.join("src/main.rs"), "fn main() {}\n").unwrap();
    revert_ok(proj, &fx.cargo_home, "pre-v5 overwrite");
    assert_eq!(
        std::fs::read(proj.join("Cargo.toml")).unwrap(),
        fx.manifest_before
    );
    assert_eq!(
        std::fs::read(proj.join("Cargo.lock")).unwrap(),
        fx.lock_before
    );
}
