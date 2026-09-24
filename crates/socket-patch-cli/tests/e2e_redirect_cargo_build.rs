//! Real-cargo hosted-mode (registry-protocol) capstone e2e — the full-chain
//! proof for `scan --mode hosted` on the cargo-sparse override.
//!
//! Unlike npm (which pins a hosted artifact URL directly in the lockfile),
//! cargo's hosted redirect speaks the REGISTRY PROTOCOL: the reference
//! endpoint hands back a `cargo-sparse` registryOverride and the rewriter
//! wires THREE files — `.cargo/config.toml` gains a
//! `[registries.socket-patch-<uuid>]` sparse-index definition, the
//! `Cargo.toml` dependency gains `registry = "socket-patch-<uuid>"`, and the
//! `Cargo.lock` `[[package]]` entry's `source`/`checksum` are repointed at
//! the hosted index + the PATCHED `.crate`'s sha256. This test proves every
//! link against the REAL cargo:
//!
//!   1. A tiny consumer crate depending on the dep-free `cfg-if` is built
//!      with a private CARGO_HOME (network to crates.io for fixture setup
//!      only), extracting the real registry sources.
//!   2. A PATCHED `.crate` is rebuilt from those ACTUAL crates.io bytes (a
//!      `///`-documented `pub fn socket_patched() -> u32 { 1 }` appended to
//!      `src/lib.rs`) and served from wiremock alongside the discovery /
//!      reference / view API mocks AND a real sparse index
//!      (`config.json` + per-crate index file + download route).
//!   3. `scan --mode hosted --json --vex …` (the real binary): the three-file
//!      rewrite lands, the ledger embeds the patch record, and the in-run
//!      VEX is the unverified `(redirected)` attestation.
//!   4. FRESH-CHECKOUT PROOF: only Cargo.toml + Cargo.lock + `.cargo/` +
//!      `src/` + `.socket/` travel; `cargo fetch --locked` with an EMPTY
//!      CARGO_HOME pulls the patched `.crate` from wiremock (byte-asserted
//!      against the cache), and an offline compile oracle
//!      (`cfg_if::socket_patched()`) proves the patched bytes are what cargo
//!      extracts and links.
//!   5. POST-INSTALL VERIFIED VEX: `socket-patch vex` hash-verifies the
//!      extracted registry sources against the ledger record and emits the
//!      `(redirected)` statement.
//!
//! The negative twin serves TAMPERED `.crate` bytes while the index cksum
//! and the lockfile checksum keep the real sha256: the fresh `cargo fetch
//! --locked` must FAIL with a checksum error — the pin is enforcement, not
//! decoration.
//!
//! A get-driven twin (`cargo_get_uuid_hosted_fresh_checkout_fetch`) drives
//! the SAME fixture through `get <uuid> --mode hosted` (v3.6) — parity by
//! construction, since get hands the (purl, uuid) pair to scan's extracted
//! run_redirect_selected engine — and re-proves the fresh-checkout fetch.
//! Hosted get writes NO manifest and NO blobs (the redirect ledger is the
//! persistence) and has no `--vex`.
//!
//! MANIFEST-LESS VEX (both drivers): the fresh checkout above is then
//! driven through the lockfile-discovery steps with the shared
//! `vex_e2e_common` helpers against a separate patch-API stand-in —
//! (1) no manifest, ledger kept → `(redirected)` from the ledger record,
//! zero API calls; embedded `apply --vex` attests too; (2) ledger deleted →
//! the lockfile's hosted `source` + the API's record still attest — with
//! the patched copy extracted, and with nothing installed (the lock's
//! checksum pin) — and embedded `apply --vex` / `scan --vex` too; (3) `--offline` with no ledger →
//! `record_unavailable`, zero API requests; (4) the lockfile reverted to
//! crates.io with the ledger restored — the stale lock alone (the patched
//! copy still extracted), and the full three-file revert re-fetched from
//! crates.io by the real cargo — → NOT attested (`redirect_unwired`), also
//! under `--no-verify`.
//!
//! Toolchain / lock format: `cargo_e2e_matrix` (`SOCKET_PATCH_CARGO_E2E_*`)
//! runs every step under a pinned cargo release and re-encodes the
//! baseline `Cargo.lock` as v1–v4 before the redirect; the rewrite must keep
//! that format and `cargo fetch --locked` must accept it.
//!
//! Skips (with a println) when `cargo` is missing or crates.io is
//! unreachable for the fixture build (a failure instead under
//! `SOCKET_PATCH_CARGO_E2E_REQUIRED=1`); every assertion after that is hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
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
const DEP: &str = "cfg-if";
/// Canonical lowercase patch uuid — names the managed cargo registry
/// (`socket-patch-<uuid>`) and the hosted URL path level.
const UUID: &str = "6b7c8d9e-0f1a-4a1b-8c2d-3e4f5a6b7c8d";
/// Access-token uuid segment of the hosted download URL (opaque to the CLI —
/// it just writes what the reference endpoint hands back).
const TOKEN: &str = "33333333-3333-4333-8333-333333333333";
const GHSA: &str = "GHSA-redirect-cargo-real";
const CVE: &str = "CVE-2026-2222";
const PRODUCT: &str = "pkg:cargo/app@1.0.0";
/// Appended to the dep's `src/lib.rs`. Doc comment kept from the vendor
/// capstone (cfg-if denies `missing_docs`; registry deps get `--cap-lints
/// allow`, but the suffix stays identical so both capstones patch the same
/// bytes).
const PATCH_SUFFIX: &str =
    "\n/// Socket-patch capstone marker (added by the hosted patch).\npub fn socket_patched() -> u32 { 1 }\n";

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
/// private CARGO_HOME and no ambient CARGO_TARGET_DIR.
fn cargo(cwd: &Path, args: &[&str], cargo_home: &Path) -> Output {
    cargo_e2e_matrix::cargo_command(cwd, cargo_home)
        .args(args)
        .output()
        .expect("failed to run cargo")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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

/// Find the extracted registry source dir `<cargo_home>/registry/src/<idx>/<leaf>/`.
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

/// Find the downloaded `.crate` file `<cargo_home>/registry/cache/<idx>/<leaf>`.
fn find_cached_crate(cargo_home: &Path, leaf: &str) -> Option<PathBuf> {
    let cache = cargo_home.join("registry").join("cache");
    for entry in std::fs::read_dir(&cache).ok()? {
        let candidate = entry.ok()?.path().join(leaf);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// The sparse-index path for `name` relative to the index root (the crates.io
/// sparse layout: 1/, 2/, 3/<c>/, or <first two>/<next two>/).
fn sparse_index_rel(name: &str) -> String {
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

/// Rebuild a `.crate` (gzipped tar rooted at `<name>-<version>/`) from the
/// extracted registry sources with the patched `src/lib.rs` swapped in. The
/// cargo-generated `.cargo-checksum.json` is dropped — a published `.crate`
/// never carries one (cargo synthesizes it at extraction time).
fn build_patched_crate(
    stage_root: &Path,
    crate_dir: &Path,
    version: &str,
    patched: &[u8],
) -> Vec<u8> {
    let leaf = format!("{DEP}-{version}");
    let pkg_dir = stage_root.join(&leaf);
    copy_dir_recursive(crate_dir, &pkg_dir);
    let _ = std::fs::remove_file(pkg_dir.join(".cargo-checksum.json"));
    std::fs::write(pkg_dir.join("src/lib.rs"), patched).unwrap();

    let mut bytes = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::new(6));
        let mut builder = tar::Builder::new(enc);
        builder
            .append_dir_all(&leaf, &pkg_dir)
            .expect("tar the patched crate");
        builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip");
    }
    bytes
}

/// Stage the consumer project + private CARGO_HOME and run the baseline
/// build (which extracts cfg-if into `registry/src/`). Returns
/// `(proj, cargo_home, locked cfg-if version, registry src dir)` or `None`
/// when the toolchain/network makes the fixture impossible (caller skips).
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
            &format!("e2e_redirect_cargo_build ({tag})"),
            &format!(
                "baseline `cargo build` failed (crates.io unreachable?):\n{}",
                String::from_utf8_lossy(&build.stderr)
            ),
        );
        return None;
    }
    // The matrix's lock format (v1–v4), re-encoded from what the toolchain
    // wrote: the committed-lockfile shape the rewrite must meet.
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

/// Which CLI invocation drives the hosted redirect in
/// [`redirect_scanned_project`]. The fixture, API/index mocks, three-file
/// rewrite, and ledger assertions are identical — both routes flow through
/// scan's `run_redirect_selected` engine; only the argv and the JSON
/// envelope framing differ.
#[derive(Clone, Copy, PartialEq)]
enum Driver {
    /// `scan --mode hosted --json --yes --vex …` (the original capstone).
    ScanVex,
    /// `get <uuid> --mode hosted --json --yes` — no `--vex` (get has none),
    /// and the uuid identifier path needs no search-endpoint mocks.
    GetUuid,
}

/// Everything the post-redirect legs need. `tmp` owns the whole tree;
/// `_server` keeps the sparse index + download routes alive through the
/// fresh `cargo fetch`.
struct RedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    version: String,
    /// Pre-redirect (crates.io) `Cargo.toml` / `Cargo.lock`.
    baseline_toml: String,
    baseline_lock: String,
    /// The mock origin serving the hosted index (`--patch-server-url`).
    server_uri: String,
    /// The REAL patched `.crate` bytes (what the lockfile/index cksum pins).
    crate_bytes: Vec<u8>,
    /// The patched `src/lib.rs` content.
    patched: Vec<u8>,
    _server: MockServer,
}

/// Steps 1–3 of the module doc: real fixture build, patched `.crate` + API
/// mocks + sparse-index routes, the `driver` invocation (scan's capstone
/// argv or the get-uuid twin), and the envelope / three-file-rewrite /
/// ledger assertions. When `tamper_served_crate` is set, the download route
/// serves DIFFERENT bytes than the sha256 pinned into the index + lockfile
/// — the negative twin's premise. `None` = skip (message already printed).
async fn redirect_scanned_project(
    tag: &str,
    tamper_served_crate: bool,
    driver: Driver,
) -> Option<RedirectFixture> {
    if !cargo_e2e_matrix::cargo_available(&format!("e2e_redirect_cargo_build ({tag})")) {
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (proj, cargo_home, version, crate_dir) = stage_fixture(tmp.path(), tag)?;
    let purl = format!("pkg:cargo/{DEP}@{version}");
    // The committed crates.io state the redirect replaces (the revert leg).
    let baseline_toml = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    let baseline_lock = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    let lock_format = cargo_e2e_matrix::lock_format(&baseline_lock);

    // 2. Patched `.crate` from the ACTUAL crates.io bytes. The index cksum
    //    and (through the rewriter) the Cargo.lock checksum are ALWAYS the
    //    real tarball's sha256; the negative twin only tampers what the
    //    download route SERVES, so the pin is what catches the swap.
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    assert!(
        !String::from_utf8_lossy(&orig).contains("socket_patched"),
        "pristine registry sources must not carry the marker"
    );
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    let crate_bytes = build_patched_crate(
        &tmp.path().join("crate-stage"),
        &crate_dir,
        &version,
        &patched,
    );
    let cksum = sha256_hex(&crate_bytes);
    let served: Vec<u8> = if tamper_served_crate {
        [crate_bytes.as_slice(), &[0u8][..]].concat()
    } else {
        crate_bytes.clone()
    };

    // 3. API mocks + the sparse registry cargo will speak to. The index URL
    //    is what the rewriter writes verbatim into `.cargo/config.toml` and
    //    the Cargo.lock `source`.
    let server = MockServer::start().await;
    // Production-shaped index path (`/patch-registry/cargo/<token>/<uuid>/
    // index/`): manifest-less VEX reads the patch uuid out of the lock's
    // `source` (the last canonical-uuid segment, never the uuid-shaped
    // token) once `--patch-server-url` admits this origin.
    let index_rel = format!("/patch-registry/cargo/{TOKEN}/{UUID}/index");
    let index_url = format!("sparse+{}{index_rel}/", server.uri());
    let hosted_url = format!(
        "{}/patch/cargo/{DEP}/{version}/{TOKEN}/{UUID}/{DEP}-{version}.crate",
        server.uri()
    );
    // Batch discovery: the crawled crate has one free patch.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID, "purl": purl, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "cargo redirect capstone fixture"
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
                "uuid": UUID, "purl": purl,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    // Reference endpoint: granted, carrying the cargo-sparse registry
    // override (the identifier shape the TS reference builder emits — name /
    // version / cargoCksumSha256).
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": hosted_url,
                    "purl": purl,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": hosted_url,
                        "integrity": { "sha256": cksum }
                    }],
                    "registryOverride": {
                        "kind": "cargo-sparse",
                        "indexUrl": index_url,
                        "identifiers": {
                            "name": DEP,
                            "version": version,
                            "cargoCksumSha256": cksum,
                        }
                    }
                }
            }
        })))
        .mount(&server)
        .await;
    // View endpoint: the patch record (REAL before/after hashes of the
    // registry vs patched bytes) the redirect run persists for VEX.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "src/lib.rs": {
                    "beforeHash": compute_git_sha256_from_bytes(&orig),
                    "afterHash": compute_git_sha256_from_bytes(&patched),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-2222"],
                    "summary": "cargo redirect capstone vuln",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(&server)
        .await;
    // The sparse index cargo speaks to at install time: config.json names
    // the download endpoint (no `{crate}` markers, so cargo appends
    // `/{crate}/{version}/download`), the per-crate index file pins the
    // PATCHED tarball's cksum, and the download route serves the bytes.
    Mock::given(method("GET"))
        .and(path(format!("{index_rel}/config.json")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dl": format!("{}/dl", server.uri()),
            "api": server.uri(),
        })))
        .mount(&server)
        .await;
    let index_line = serde_json::json!({
        "name": DEP,
        "vers": version,
        "deps": [],
        "cksum": cksum,
        "features": {},
        "yanked": false,
    })
    .to_string();
    Mock::given(method("GET"))
        .and(path(format!("{index_rel}/{}", sparse_index_rel(DEP))))
        .respond_with(ResponseTemplate::new(200).set_body_raw(index_line, "text/plain"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/dl/{DEP}/{version}/download")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(served, "application/octet-stream"))
        .mount(&server)
        .await;

    // The driver invocation. Scan: `--mode hosted --vex` — the three-file
    // rewrite + the in-run (unverified) attestation (`--mode hosted` is the
    // documented spelling of `--redirect`). Get: `get <uuid> --mode hosted`
    // — same engine, get's confirm gate auto-accepted by --json/--yes, no
    // --vex (get has none).
    let server_uri = server.uri();
    let argv: Vec<&str> = match driver {
        Driver::ScanVex => vec![
            "scan",
            "--mode",
            "hosted",
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
            proj.to_str().unwrap(),
            "--api-url",
            &server_uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    };
    let (code, stdout, stderr) = run_socket(&proj, &argv, &cargo_home);
    assert_eq!(
        code, 0,
        "hosted redirect run ({tag}) failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("hosted --json output is not JSON: {e}\nstdout:\n{stdout}"));
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["redirect"]["mode"], "hosted", "envelope: {env}");
    // Cargo confirmation is TRANSACTIONAL: the count comes from
    // confirmed_cargo_uuids — a grant only counts once the three-file
    // rewrite actually landed.
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "exactly one dep redirected: {env}"
    );
    match driver {
        Driver::ScanVex => {
            assert_eq!(env["vex"]["path"], "out.vex.json", "vex block: {env}");
            assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
            assert_eq!(
                env["vex"]["verified"], false,
                "in-run hosted VEX is attested from the ledger, not hash-verified: {env}"
            );
        }
        Driver::GetUuid => {
            // Get's base envelope wraps the nested redirect block: found
            // counts the resolved patch; downloaded/applied are ABSENT
            // (nothing lands in .socket/) and get has no --vex.
            assert_eq!(env["found"], 1, "get envelope: {env}");
            assert!(env["vex"].is_null(), "get has no --vex: {env}");
            assert!(
                env["downloaded"].is_null() && env["applied"].is_null(),
                "hosted get must not report downloaded/applied — nothing \
                 is persisted under .socket/ but the ledger: {env}"
            );
        }
    }

    // The three-file rewrite (the cargo contract row).
    let reg = format!("socket-patch-{UUID}");
    let cargo_toml = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
    assert!(
        cargo_toml.contains(&format!("registry = \"{reg}\"")),
        "Cargo.toml dep must gain the managed registry:\n{cargo_toml}"
    );
    let config = std::fs::read_to_string(proj.join(".cargo/config.toml"))
        .expect("scan must create .cargo/config.toml");
    assert!(
        config.contains(&format!("[registries.{reg}]")) && config.contains(&index_url),
        "config must define the managed sparse registry:\n{config}"
    );
    let lock_text = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    let block = package_block(&lock_text, DEP).expect("cfg-if lock entry must survive");
    assert!(
        block.contains(&format!("source = \"{index_url}\"")),
        "lock source must be the hosted sparse index:\n{block}"
    );
    // The rewrite keeps the committed lock format, and the entry's pin is
    // the PATCHED .crate's sha256 wherever that format keeps checksums
    // (inline for v2+, `[metadata]` for v1).
    assert_eq!(
        cargo_e2e_matrix::lock_format(&lock_text),
        lock_format,
        "the hosted rewrite must keep the lock format:\n{lock_text}"
    );
    let pinned = cargo_e2e_matrix::parse_lock(&lock_text)
        .into_iter()
        .find(|p| p.name == DEP)
        .and_then(|p| p.checksum);
    assert_eq!(
        pinned.as_deref(),
        Some(cksum.as_str()),
        "lock checksum must be the PATCHED .crate's sha256:\n{lock_text}"
    );

    // Ledger embeds the patch record so a post-install `vex` can verify.
    let ledger = std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA),
        "redirect ledger must embed the patch record + vulnerability: {ledger}"
    );

    if driver == Driver::GetUuid {
        // Parity with scan --mode hosted: the ledger IS the persistence.
        assert!(
            !proj.join(".socket/manifest.json").exists(),
            "get --mode hosted must NOT write the manifest"
        );
        assert!(
            !proj.join(".socket/blobs").exists(),
            "get --mode hosted must NOT persist blobs"
        );
    }

    Some(RedirectFixture {
        tmp,
        proj,
        version,
        baseline_toml,
        baseline_lock,
        server_uri: server.uri(),
        crate_bytes,
        patched,
        _server: server,
    })
}

/// New dir holding ONLY what a git checkout would carry — Cargo.toml,
/// Cargo.lock, `.cargo/`, `src/`, `.socket/` — then `cargo fetch --locked`
/// against an EMPTY CARGO_HOME. Returns the fresh dir, its cargo home, and
/// the fetch output (asserted by each test: success for the real `.crate`,
/// checksum failure for the tampered one).
fn fresh_checkout_cargo_fetch(fx: &RedirectFixture) -> (PathBuf, PathBuf, Output) {
    let fresh = fx.tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join("Cargo.toml"), fresh.join("Cargo.toml")).unwrap();
    std::fs::copy(fx.proj.join("Cargo.lock"), fresh.join("Cargo.lock")).unwrap();
    copy_dir_recursive(&fx.proj.join(".cargo"), &fresh.join(".cargo"));
    copy_dir_recursive(&fx.proj.join("src"), &fresh.join("src"));
    copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));

    let fresh_home = fx.tmp.path().join("fresh-cargo-home");
    std::fs::create_dir_all(&fresh_home).unwrap();
    let fetch = cargo(&fresh, &["fetch", "--locked"], &fresh_home);
    (fresh, fresh_home, fetch)
}

// ── manifest-less VEX (lockfile discovery) ────────────────────────────

/// Everything the manifest-less steps need, owned (they run on a blocking
/// thread: the shared `PatchApi` brings its own runtime).
struct ManifestlessHosted {
    /// The fresh checkout (`cargo fetch --locked` already ran in it).
    fresh: PathBuf,
    /// Its CARGO_HOME, holding the extracted hosted (patched) sources.
    fresh_home: PathBuf,
    /// Scratch root for the revert checkout.
    scratch: PathBuf,
    purl: String,
    patched: Vec<u8>,
    baseline_toml: String,
    baseline_lock: String,
    /// The mock origin serving the hosted index + the org-scoped API.
    server_uri: String,
}

impl ManifestlessHosted {
    fn new(fx: &RedirectFixture, fresh: &Path, fresh_home: &Path) -> Self {
        Self {
            fresh: fresh.to_path_buf(),
            fresh_home: fresh_home.to_path_buf(),
            scratch: fx.tmp.path().join("manifestless"),
            purl: format!("pkg:cargo/{DEP}@{}", fx.version),
            patched: fx.patched.clone(),
            baseline_toml: fx.baseline_toml.clone(),
            baseline_lock: fx.baseline_lock.clone(),
            server_uri: fx.server_uri.clone(),
        }
    }

    /// Run [`Self::steps`] off the async runtime (and re-raise its panic).
    async fn run(self) {
        if let Err(e) = tokio::task::spawn_blocking(move || self.steps()).await {
            std::panic::resume_unwind(e.into_panic());
        }
    }

    /// A standalone run against `api` for the checkout at `cargo_home`,
    /// hosted references on the fixture origin admitted.
    fn vex_run(&self, api: &PatchApi, cargo_home: &Path) -> VexRun {
        VexRun {
            product: Some(PRODUCT.to_string()),
            patch_server_url: Some(self.server_uri.clone()),
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
        let ledger_path = fresh.join(socket_patch_core::patch::redirect::REDIRECT_STATE_REL);
        let run = self.vex_run(&api, &self.fresh_home);

        // (1) No manifest (hosted never writes one), ledger kept: the
        //     ledger's record attests, verified against the extracted
        //     hosted copy — no API call.
        strip_manifest(fresh);
        assert!(ledger_path.is_file(), "the redirect ledger travels");
        let out = run_vex(&bin, fresh, &run);
        assert_eq!(out.code, Some(0), "(1) ledger-backed:\n{out}");
        assert_attested(out.doc(), &self.purl, UUID, Marker::Redirected, vulns);
        assert_eq!(
            api.view_requests(UUID),
            0,
            "(1) the ledger record needs no API"
        );
        let out = run_vex(&bin, fresh, &run.clone().via(VexVia::Apply));
        assert_eq!(out.code, Some(0), "(1) apply --vex:\n{out}");
        assert_eq!(
            out.envelope["status"], "noManifest",
            "(1) apply --vex:\n{out}"
        );
        assert_attested(out.doc(), &self.purl, UUID, Marker::Redirected, vulns);

        // (2) Ledgers deleted: the lock's hosted `source` names the patch;
        //     the record comes from the API.
        let ledger = std::fs::read(&ledger_path).unwrap();
        strip_ledgers(fresh);
        let out = run_vex(&bin, fresh, &run);
        assert_eq!(out.code, Some(0), "(2) lockfile-only:\n{out}");
        assert_attested(out.doc(), &self.purl, UUID, Marker::Redirected, vulns);
        assert!(
            api.view_requests(UUID) >= 1,
            "(2) the record came from the API"
        );
        let out = run_vex(&bin, fresh, &run.clone().via(VexVia::Apply));
        assert_eq!(out.code, Some(0), "(2) apply --vex:\n{out}");
        assert_eq!(
            out.envelope["status"], "noManifest",
            "(2) apply --vex:\n{out}"
        );
        assert_attested(out.doc(), &self.purl, UUID, Marker::Redirected, vulns);
        // (2b) Not installed at all (a lockfile-only CI checkout: EMPTY
        //      CARGO_HOME): the lock's checksum pin of the patched .crate
        //      is the evidence — in every lock format (v1 keeps it in
        //      `[metadata]`).
        let empty_home = self.scratch.join("empty-cargo-home");
        std::fs::create_dir_all(&empty_home).unwrap();
        let out = run_vex(&bin, fresh, &self.vex_run(&api, &empty_home));
        assert_eq!(out.code, Some(0), "(2b) not installed:\n{out}");
        assert_attested(out.doc(), &self.purl, UUID, Marker::Redirected, vulns);
        // Embedded read-only `scan --vex`, authenticated against the
        // fixture's org-scoped API (batch discovery + the patch view).
        let scan = VexRun {
            via: VexVia::Scan,
            api_url: Some(self.server_uri.clone()),
            api_token: Some("fake".to_string()),
            org: Some(ORG.to_string()),
            proxy_url: None,
            ..run.clone()
        };
        let out = run_vex(&bin, fresh, &scan);
        assert_eq!(out.code, Some(0), "(2) scan --vex:\n{out}");
        assert_attested(out.doc(), &self.purl, UUID, Marker::Redirected, vulns);
        assert!(
            !fresh.join(".socket/manifest.json").exists(),
            "no VEX step writes the manifest"
        );

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

        // (4a) The lock reverted to crates.io (ledger restored, the patched
        //      hosted copy still extracted, the Cargo.toml pin + registry
        //      definition left over): the stale ledger never attests.
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
            assert_not_attested(&out.envelope, &self.purl, "redirect_unwired");
            assert_absent(out.doc.as_ref(), &self.purl);
        }

        // (4b) The full three-file revert, installed for real from
        //      crates.io, with the ledger kept.
        let revert = self.scratch.join("reverted");
        let revert_home = self.scratch.join("reverted-cargo-home");
        std::fs::create_dir_all(revert.join(".socket/vendor")).unwrap();
        std::fs::create_dir_all(&revert_home).unwrap();
        std::fs::write(revert.join("Cargo.toml"), &self.baseline_toml).unwrap();
        std::fs::write(revert.join("Cargo.lock"), &self.baseline_lock).unwrap();
        copy_dir_recursive(&fresh.join("src"), &revert.join("src"));
        std::fs::write(
            revert.join(socket_patch_core::patch::redirect::REDIRECT_STATE_REL),
            &ledger,
        )
        .unwrap();
        let fetch = cargo(&revert, &["fetch", "--locked"], &revert_home);
        assert!(
            fetch.status.success(),
            "(4b) the reverted checkout fetches from crates.io:\n{}",
            String::from_utf8_lossy(&fetch.stderr)
        );
        let leaf = self.purl.rsplit('/').next().unwrap().replace('@', "-");
        let pristine = find_registry_crate(&revert_home, &leaf)
            .map(|dir| std::fs::read(dir.join("src/lib.rs")).unwrap());
        if let Some(pristine) = pristine {
            assert!(
                !String::from_utf8_lossy(&pristine).contains("socket_patched"),
                "(4b) the reverted install is crates.io's copy"
            );
        }
        let run = self.vex_run(&api, &revert_home);
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
            assert_not_attested(&out.envelope, &self.purl, "redirect_unwired");
            assert_absent(out.doc.as_ref(), &self.purl);
        }
    }
}

// ── the capstone ──────────────────────────────────────────────────────

// multi_thread: the CLI/cargo subprocesses block a worker thread while
// wiremock keeps serving the API + index + download routes on the others.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_fresh_checkout_fetch_pulls_patched_crate_and_vex_verifies() {
    let Some(fx) = redirect_scanned_project("main", false, Driver::ScanVex).await else {
        return;
    };

    // 4. FRESH-CHECKOUT PROOF: cargo pulls the patched `.crate` from the
    //    hosted sparse registry because the committed three-file rewrite
    //    says so.
    let (fresh, fresh_home, fetch) = fresh_checkout_cargo_fetch(&fx);
    assert!(
        fetch.status.success(),
        "fresh-checkout `cargo fetch --locked` must succeed from the hosted registry.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fetch.stdout),
        String::from_utf8_lossy(&fetch.stderr),
    );
    let leaf = format!("{DEP}-{}", fx.version);
    let cached = find_cached_crate(&fresh_home, &format!("{leaf}.crate"))
        .expect("fetch must land the .crate in <CARGO_HOME>/registry/cache");
    assert_eq!(
        std::fs::read(&cached).unwrap(),
        fx.crate_bytes,
        "the fetched .crate must be byte-identical to the hosted patched tarball"
    );

    // COMPILE ORACLE (offline — everything needed was fetched above): the
    // consumer references the patched-only symbol, so it links iff cargo
    // extracted the PATCHED bytes.
    std::fs::write(
        fresh.join("src/main.rs"),
        "fn main() { println!(\"MARKER:{}\", cfg_if::socket_patched()); }\n",
    )
    .unwrap();
    let run = cargo(&fresh, &["run", "-q", "--locked", "--offline"], &fresh_home);
    assert!(
        run.status.success(),
        "offline `cargo run --locked` must link the hosted patched crate.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    );
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("MARKER:1"),
        "patched symbol must be linked: {}",
        String::from_utf8_lossy(&run.stdout)
    );
    let extracted = find_registry_crate(&fresh_home, &leaf)
        .expect("the build must extract the crate under <CARGO_HOME>/registry/src");
    assert_eq!(
        std::fs::read(extracted.join("src/lib.rs")).unwrap(),
        fx.patched,
        "extracted registry sources must hold the patched bytes"
    );

    // 5. POST-INSTALL VERIFIED VEX: default verify mode hash-verifies the
    //    extracted registry sources against the ledger's patch record.
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
        &fresh_home,
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
    assert_eq!(
        stmts[0]["products"][0]["subcomponents"][0]["@id"],
        format!("pkg:cargo/{DEP}@{}", fx.version)
    );
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (redirected)"),
        "the post-install (hash-verified) attestation must carry the (redirected) marker"
    );

    // 6. Manifest-less VEX on the same fresh checkout.
    ManifestlessHosted::new(&fx, &fresh, &fresh_home)
        .run()
        .await;
}

/// get-driven twin (v3.6): `get <uuid> --mode hosted --json --yes` must land
/// the SAME three-file rewrite + ledger as the scan capstone (asserted
/// inside the shared fixture — parity by construction through
/// run_redirect_selected, redirected count via the transactional
/// confirmed_cargo_uuids), with NO manifest and NO blobs. Then the
/// fresh-checkout proof: `cargo fetch --locked` against an EMPTY CARGO_HOME
/// pulls the patched `.crate` from the hosted sparse registry,
/// byte-identical to the served tarball.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_get_uuid_hosted_fresh_checkout_fetch() {
    let Some(fx) = redirect_scanned_project("get-uuid", false, Driver::GetUuid).await else {
        return;
    };

    let (fresh, fresh_home, fetch) = fresh_checkout_cargo_fetch(&fx);
    assert!(
        fetch.status.success(),
        "fresh-checkout `cargo fetch --locked` after `get --mode hosted` must succeed from the \
         hosted registry.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fetch.stdout),
        String::from_utf8_lossy(&fetch.stderr),
    );
    let leaf = format!("{DEP}-{}", fx.version);
    let cached = find_cached_crate(&fresh_home, &format!("{leaf}.crate"))
        .expect("fetch must land the .crate in <CARGO_HOME>/registry/cache");
    assert_eq!(
        std::fs::read(&cached).unwrap(),
        fx.crate_bytes,
        "the fetched .crate must be byte-identical to the hosted patched tarball"
    );

    // Manifest-less VEX: `cargo fetch` only downloads, so extract the
    // sources the way the build does (an offline build) first — the
    // installed-tree check then hashes the hosted copy.
    let build = cargo(
        &fresh,
        &["build", "-q", "--locked", "--offline"],
        &fresh_home,
    );
    assert!(
        build.status.success(),
        "offline build of the get-driven checkout:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    ManifestlessHosted::new(&fx, &fresh, &fresh_home)
        .run()
        .await;
}

/// Negative twin: the download route serves TAMPERED bytes while the index
/// cksum + the committed Cargo.lock checksum pin the REAL `.crate`'s sha256
/// — the fresh `cargo fetch --locked` must refuse. This is what makes the
/// hosted redirect safe to commit: a compromised or swapped hosted artifact
/// cannot slip past the pin.
#[tokio::test(flavor = "multi_thread")]
async fn cargo_hosted_tampered_crate_fails_fresh_fetch() {
    let Some(fx) = redirect_scanned_project("tampered", true, Driver::ScanVex).await else {
        return;
    };

    let (_fresh, _fresh_home, fetch) = fresh_checkout_cargo_fetch(&fx);
    assert!(
        !fetch.status.success(),
        "cargo fetch MUST fail when the served .crate does not match the pinned sha256.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&fetch.stdout),
        String::from_utf8_lossy(&fetch.stderr),
    );
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&fetch.stdout),
        String::from_utf8_lossy(&fetch.stderr)
    );
    assert!(
        chatter.to_lowercase().contains("checksum"),
        "the failure must be the checksum check, not something incidental:\n{chatter}"
    );
}
