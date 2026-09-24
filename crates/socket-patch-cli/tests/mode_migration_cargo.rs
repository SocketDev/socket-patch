//! Real-cargo mode-migration e2e: vendored ⇄ hosted takeovers must leave the
//! project FULLY in the new mode — or refuse. The vendored wiring is the
//! root `Cargo.toml`'s `[patch.crates-io]` (v5); the hosted wiring is the
//! `registry = "socket-patch-<uuid>"` pin in the same manifest plus the
//! `.cargo/config.toml` registry block — so both directions edit Cargo.toml
//! and each must leave none of the other mode's lines behind.
//!
//! Adapted from the audit probes that empirically proved findings C1–C7 (the
//! cargo mode-takeover bug class): both directions used to exit 0 while
//! leaving the project unbuildable under `--locked` (leftover
//! `[patch.crates-io]` after a hosted takeover; a surviving
//! `registry = "socket-patch-…"` Cargo.toml pin after a vendored takeover), a
//! double takeover destroyed the unrecoverable crates.io lock originals in
//! the vendored ledger, and the takeover classifier then emitted an INVERTED
//! warning telling the user to delete the live ledger.
//!
//! Each scenario drives the REAL binary against real cargo (network used for
//! the crates.io fixture build only; the hosted registry is wiremock) and
//! proves the terminal state with `cargo build --locked` on a fresh checkout.
//!
//! MANIFEST-LESS VEX after every takeover (`vex_e2e_common`): on the fresh
//! checkout the terminal mode's patch — and ONLY it — attests with its
//! marker: `(redirected)` for the hosted uuid after vendored → hosted,
//! `(vendored)` for the vendored uuid after hosted → vendored and after the
//! A → B → A round trip. (0) with the manifest still naming the displaced
//! patch (the wired uuid wins), (1) manifest deleted / ledger kept (zero
//! API calls), (2) ledgers deleted (lockfile wiring + API record), (3)
//! `--offline` with no ledger → `record_unavailable`, zero requests. The
//! displaced patch is never attested.
//!
//! Toolchain / lock format: `cargo_e2e_matrix` (`SOCKET_PATCH_CARGO_E2E_*`).
//!
//! Skips (println) when `cargo` is missing or crates.io is unreachable for
//! the fixture build (a failure instead under
//! `SOCKET_PATCH_CARGO_E2E_REQUIRED=1`); all assertions after that are hard.

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
    Marker, PatchApi, VexRun,
};

const ORG: &str = "test-org";
const DEP: &str = "cfg-if";
const UUID_V: &str = "2b3c4d5e-6f70-4a1b-8c2d-0123456789ab"; // vendored patch
const UUID_H: &str = "6b7c8d9e-0f1a-4a1b-8c2d-3e4f5a6b7c8d"; // hosted patch
const TOKEN: &str = "33333333-3333-4333-8333-333333333333";
const GHSA: &str = "GHSA-migr-cargo-test";
/// Doc comment required: cfg-if denies `missing_docs` and path deps get no
/// `--cap-lints allow`.
const PATCH_SUFFIX: &str =
    "\n/// Socket-patch capstone marker (added by the patch).\npub fn socket_patched() -> u32 { 1 }\n";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

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

fn assert_build_ok(tag: &str, out: &Output) {
    assert!(
        out.status.success(),
        "{tag} must succeed, got {}:\nstdout=<<<{}>>>\nstderr=<<<{}>>>",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn git_sha256(content: &[u8]) -> String {
    compute_git_sha256_from_bytes(content)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn stage_patch(proj: &Path, purl: &str, before: &[u8], after: &[u8]) {
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": { purl: {
            "uuid": UUID_V,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "src/lib.rs": {
                "beforeHash": git_sha256(before),
                "afterHash": git_sha256(after),
            }},
            "vulnerabilities": { GHSA: {
                "cves": ["CVE-2026-88888"],
                "summary": "migration vuln", "severity": "high", "description": "d",
            }},
            "description": "migration patch", "license": "MIT", "tier": "free",
        }}
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(after)), after).unwrap();
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

fn package_block(lock_text: &str, name: &str) -> Option<String> {
    let needle = format!("name = \"{name}\"");
    lock_text
        .split("[[package]]")
        .find(|block| block.lines().any(|l| l.trim() == needle))
        .map(str::to_string)
}

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

fn sparse_index_rel(name: &str) -> String {
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

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
        builder.append_dir_all(&leaf, &pkg_dir).unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }
    bytes
}

/// Consumer crate fixture: build once against real crates.io to populate the
/// private CARGO_HOME + Cargo.lock. `None` (with a SKIP println) when the
/// toolchain or network is unavailable.
fn stage_fixture(tmp: &Path) -> Option<(PathBuf, PathBuf, String, PathBuf)> {
    if !cargo_e2e_matrix::cargo_available("mode_migration_cargo") {
        return None;
    }
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
            "mode_migration_cargo",
            &format!(
                "baseline cargo build failed (no cargo or no network):\n{}",
                String::from_utf8_lossy(&build.stderr)
            ),
        );
        return None;
    }
    // The matrix's lock format (v1–v4) for the committed baseline.
    cargo_e2e_matrix::apply_lock_version(&proj);
    let lock_text = std::fs::read_to_string(proj.join("Cargo.lock")).unwrap();
    let version = locked_version(&lock_text, DEP).unwrap();
    let crate_dir = find_registry_crate(&cargo_home, &format!("{DEP}-{version}")).unwrap();
    Some((proj, cargo_home, version, crate_dir))
}

/// Mount the full hosted-mode mock set (discovery + reference + view + sparse
/// index + download) for patch UUID_H over `purl`.
async fn mount_hosted_mocks(
    server: &MockServer,
    purl: &str,
    version: &str,
    crate_bytes: &[u8],
    orig: &[u8],
    patched: &[u8],
) -> String {
    let cksum = sha256_hex(crate_bytes);
    // Production-shaped index path: manifest-less VEX reads the hosted
    // uuid out of the lock's `source` (with `--patch-server-url`).
    let index_rel = format!("/patch-registry/cargo/{TOKEN}/{UUID_H}/index");
    let index_url = format!("sparse+{}{index_rel}/", server.uri());
    let hosted_url = format!(
        "{}/patch/cargo/{DEP}/{version}/{TOKEN}/{UUID_H}/{DEP}-{version}.crate",
        server.uri()
    );
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID_H, "purl": purl, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "cargo migration fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID_H, "purl": purl,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID_H: {
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
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID_H}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID_H,
            "purl": purl,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "src/lib.rs": {
                    "beforeHash": compute_git_sha256_from_bytes(orig),
                    "afterHash": compute_git_sha256_from_bytes(patched),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-2222"],
                    "summary": "migration vuln", "severity": "high", "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{index_rel}/config.json")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dl": format!("{}/dl", server.uri()),
            "api": server.uri(),
        })))
        .mount(server)
        .await;
    let index_line = serde_json::json!({
        "name": DEP, "vers": version, "deps": [], "cksum": cksum,
        "features": {}, "yanked": false,
    })
    .to_string();
    Mock::given(method("GET"))
        .and(path(format!("{index_rel}/{}", sparse_index_rel(DEP))))
        .respond_with(ResponseTemplate::new(200).set_body_raw(index_line, "text/plain"))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/dl/{DEP}/{version}/download")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(crate_bytes.to_vec(), "application/octet-stream"),
        )
        .mount(server)
        .await;
    index_url
}

/// Manifest-less VEX over a post-takeover fresh checkout: `wired` (uuid +
/// marker) must attest, `displaced` never. Runs on a blocking thread (the
/// shared `PatchApi` brings its own runtime).
struct TakeoverVex {
    fresh: PathBuf,
    home: PathBuf,
    purl: String,
    patched: Vec<u8>,
    wired: (&'static str, Marker),
    displaced: &'static str,
    /// The hosted index origin (`--patch-server-url`).
    server_uri: String,
}

impl TakeoverVex {
    async fn run(self) {
        if let Err(e) = tokio::task::spawn_blocking(move || self.steps()).await {
            std::panic::resume_unwind(e.into_panic());
        }
    }

    fn steps(self) {
        let bin = binary();
        // Each patch's own alias: the vendored record (the staged
        // manifest's) and the hosted one (the view mock's) differ.
        let vulns_of = |u: &str| -> [(&'static str, &'static [&'static str]); 1] {
            if u == UUID_V {
                [(GHSA, &["CVE-2026-88888"])]
            } else {
                [(GHSA, &["CVE-2026-2222"])]
            }
        };
        let (uuid, marker) = self.wired;
        let vulns = vulns_of(uuid);
        let vulns = vulns.as_slice();
        let after = vex_e2e_common::git_sha256(&self.patched);
        let view = |u: &str| {
            vex_e2e_common::patch_view(u, &self.purl, &[("src/lib.rs", &after)], &vulns_of(u))
        };
        let api = PatchApi::start(vec![
            (UUID_V.to_string(), view(UUID_V)),
            (UUID_H.to_string(), view(UUID_H)),
        ]);
        let run = VexRun {
            product: Some("pkg:cargo/app@1.0.0".to_string()),
            patch_server_url: Some(self.server_uri.clone()),
            ..VexRun::online(&api)
        }
        .env("CARGO_HOME", &self.home);
        let fresh = self.fresh.as_path();
        let only_wired = |doc: &serde_json::Value, step: &str| {
            assert_attested(doc, &self.purl, uuid, marker, vulns);
            assert!(
                !doc.to_string().contains(self.displaced),
                "{step}: the displaced patch {} must never be attested: {doc:#}",
                self.displaced
            );
        };

        // (0) The manifest (still naming the displaced vendored patch
        //     after a hosted takeover) is present: the wired uuid wins.
        if fresh.join(".socket/manifest.json").exists() {
            let out = run_vex(&bin, fresh, &run);
            assert_eq!(out.code, Some(0), "(0) with manifest:\n{out}");
            only_wired(out.doc(), "(0)");
        }
        // (1) Manifest deleted, ledger kept.
        strip_manifest(fresh);
        let before = api.request_count();
        let out = run_vex(&bin, fresh, &run);
        assert_eq!(out.code, Some(0), "(1) ledger-backed:\n{out}");
        only_wired(out.doc(), "(1)");
        assert_eq!(
            api.request_count(),
            before,
            "(1) the ledger record needs no API"
        );
        // (2) Ledgers deleted: the lockfile wiring + the API's record.
        strip_ledgers(fresh);
        let out = run_vex(&bin, fresh, &run);
        assert_eq!(out.code, Some(0), "(2) lockfile-only:\n{out}");
        only_wired(out.doc(), "(2)");
        assert!(api.view_requests(uuid) >= 1, "(2) fetched the wired record");
        assert_eq!(
            api.view_requests(self.displaced),
            0,
            "(2) never asked for the displaced one"
        );
        // (3) Offline, no ledger.
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
    }
}

/// Copy ONLY the committable files to a fresh dir (the fresh-checkout proof).
fn fresh_checkout(proj: &Path, tmp: &Path, tag: &str) -> (PathBuf, PathBuf) {
    let fresh = tmp.join(format!("fresh-{tag}"));
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("Cargo.toml"), fresh.join("Cargo.toml")).unwrap();
    std::fs::copy(proj.join("Cargo.lock"), fresh.join("Cargo.lock")).unwrap();
    if proj.join(".cargo").exists() {
        copy_dir_recursive(&proj.join(".cargo"), &fresh.join(".cargo"));
    }
    copy_dir_recursive(&proj.join("src"), &fresh.join("src"));
    if proj.join(".socket").exists() {
        copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    }
    let home = tmp.join(format!("fresh-home-{tag}"));
    std::fs::create_dir_all(&home).unwrap();
    (fresh, home)
}

/// `version` tagged for `uuid` (the vendored copy's version).
fn tagged(version: &str, uuid: &str) -> String {
    socket_patch_core::vendor::cargo_tag::tag_version(version, uuid)
}

/// The dep's `Cargo.lock` entry has exactly version `want`.
fn assert_lock_version(proj: &Path, want: &str, tag: &str) {
    let lock = read(proj, "Cargo.lock");
    assert_eq!(
        locked_version(&lock, DEP).as_deref(),
        Some(want),
        "{tag}: the {DEP} lock entry version:\n{lock}"
    );
}

fn read(proj: &Path, rel: &str) -> String {
    std::fs::read_to_string(proj.join(rel)).unwrap_or_default()
}

fn vendor_ledger_claims(proj: &Path, purl: &str) -> bool {
    read(proj, ".socket/vendor/state.json").contains(purl)
}

// ── C1 / C4b: vendored → hosted takeover ────────────────────────────────────
// The hosted scan must revert the vendored state first, leave the project
// PURELY hosted (fresh checkout builds under --locked), and no later vendored
// no-op may emit the inverted `vendor_supersedes_redirect` warning.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_then_hosted_takeover_leaves_pure_hosted() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path()) else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, &orig, &patched);

    // A: vendor (offline).
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
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    assert!(
        vendor_ledger_claims(&proj, &purl),
        "vendored ledger claims the purl"
    );

    // B: hosted redirect over the vendored state — the takeover.
    let server = MockServer::start().await;
    let crate_bytes =
        build_patched_crate(&tmp.path().join("stage"), &crate_dir, &version, &patched);
    mount_hosted_mocks(&server, &purl, &version, &crate_bytes, &orig, &patched).await;
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &cargo_home,
    );
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(envelope["redirect"]["redirected"], 1, "{stdout}");
    // The takeover is surfaced, and it really reverted the vendored state.
    assert!(
        stdout.contains("redirect_takeover_reverted_vendored"),
        "takeover warning missing: {stdout}"
    );

    // The project is FULLY hosted: no leftover [patch.crates-io], no vendored
    // ledger claim, no committed vendor tree; the hosted wiring is present.
    let config = read(&proj, ".cargo/config.toml");
    let toml = read(&proj, "Cargo.toml");
    assert!(
        !config.contains("[patch.crates-io]") && !toml.contains("[patch.crates-io]"),
        "leftover [patch.crates-io] breaks every --locked build (C1): {toml}\n{config}"
    );
    assert!(
        config.contains(&format!("[registries.socket-patch-{UUID_H}]")),
        "{config}"
    );
    // The hosted lock entry is the registry version, the vendored tag gone.
    assert_lock_version(&proj, &version, "vendored -> hosted");
    assert!(
        !vendor_ledger_claims(&proj, &purl),
        "the displaced vendored ledger entry must be dropped: {}",
        read(&proj, ".socket/vendor/state.json")
    );
    assert!(
        !proj.join(format!(".socket/vendor/cargo/{UUID_V}")).exists(),
        "the orphaned committed tree must be removed"
    );
    assert!(
        proj.join(".socket/vendor/redirect-state.json").exists(),
        "hosted ledger written"
    );
    let lock_block = package_block(&read(&proj, "Cargo.lock"), DEP).unwrap_or_default();
    assert!(
        lock_block.contains("sparse+"),
        "lock points hosted: {lock_block}"
    );

    // C: fresh checkout builds under --locked (the CI contract the pre-fix
    // mixed state broke with "cannot update the lock file").
    let (fresh, home) = fresh_checkout(&proj, tmp.path(), "c");
    assert_build_ok(
        "cargo fetch --locked",
        &cargo(&fresh, &["fetch", "--locked"], &home),
    );
    assert_build_ok(
        "cargo build --locked",
        &cargo(&fresh, &["build", "--locked"], &home),
    );
    TakeoverVex {
        fresh: fresh.clone(),
        home: home.clone(),
        purl: purl.clone(),
        patched: patched.clone(),
        wired: (UUID_H, Marker::Redirected),
        displaced: UUID_V,
        server_uri: server.uri(),
    }
    .run()
    .await;

    // D: a later vendored-flow no-op must NOT emit the inverted
    // vendor_supersedes_redirect warning (C4b: pre-fix it told the user to
    // delete the LIVE hosted ledger while the lock pointed at the sparse
    // index). Empty API + no manifest = the no-manifest no-op path.
    std::fs::remove_file(proj.join(".socket/manifest.json")).unwrap();
    let empty = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(&empty)
        .await;
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "vendored",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &empty.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &cargo_home,
    );
    assert_eq!(code, 0, "vendored no-op failed: {stdout}\n{stderr}");
    assert!(
        !stdout.contains("vendor_supersedes_redirect")
            && !stderr.contains("vendor_supersedes_redirect"),
        "the inverted takeover warning must not fire (C4b): {stdout}\n{stderr}"
    );
}

// ── no-lock vendor → first build → hosted takeover ─────────────────────────
// Vendored before any Cargo.lock existed, the ledger records no lock
// originals; the first build then locks the TAGGED copy. The takeover's
// revert must drop that tag (back to the untagged sourceless entry), so the
// redirect finds the crate by its version and the project ends fully hosted
// and `--locked`-buildable — not a lock naming a tagged version nothing
// provides.
#[tokio::test(flavor = "multi_thread")]
async fn lockless_vendor_then_first_build_then_hosted_takeover() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path()) else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, &orig, &patched);
    std::fs::remove_file(proj.join("Cargo.lock")).unwrap();

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
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    assert!(stdout.contains("no_lockfile"), "{stdout}");
    assert_build_ok(
        "first build (locks the tagged copy)",
        &cargo(&proj, &["build", "--offline"], &cargo_home),
    );
    assert_lock_version(&proj, &tagged(&version, UUID_V), "first build");

    let server = MockServer::start().await;
    let crate_bytes =
        build_patched_crate(&tmp.path().join("stage"), &crate_dir, &version, &patched);
    mount_hosted_mocks(&server, &purl, &version, &crate_bytes, &orig, &patched).await;
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &cargo_home,
    );
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert!(
        stdout.contains("redirect_takeover_reverted_vendored"),
        "takeover warning missing: {stdout}"
    );
    assert!(
        !stdout.contains("redirect_cargo_lock_pkg_not_found"),
        "the reverted lock names the crate by its version: {stdout}"
    );
    assert_eq!(envelope["redirect"]["redirected"], 1, "{stdout}");
    assert_lock_version(&proj, &version, "lockless vendor -> hosted");
    let lock_block = package_block(&read(&proj, "Cargo.lock"), DEP).unwrap_or_default();
    assert!(
        lock_block.contains("sparse+"),
        "lock points hosted: {lock_block}"
    );

    let (fresh, home) = fresh_checkout(&proj, tmp.path(), "lockless");
    assert_build_ok(
        "cargo fetch --locked",
        &cargo(&fresh, &["fetch", "--locked"], &home),
    );
    assert_build_ok(
        "cargo build --locked",
        &cargo(&fresh, &["build", "--locked"], &home),
    );
}

// ── C2 / C7: hosted → vendored takeover via the plain `vendor` command ──────
// The primary migration entry point must revert the hosted edits first (from
// the redirect ledger), surface the takeover, leave the project PURELY
// vendored (fresh checkout builds offline under --locked), and a final
// `vendor --revert` must restore the pristine pre-hosted project.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_then_vendored_takeover_leaves_pure_vendored() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path()) else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    let toml_pristine = read(&proj, "Cargo.toml");
    let lock_pristine = std::fs::read(proj.join("Cargo.lock")).unwrap();

    // A: hosted redirect.
    let server = MockServer::start().await;
    let crate_bytes =
        build_patched_crate(&tmp.path().join("stage"), &crate_dir, &version, &patched);
    mount_hosted_mocks(&server, &purl, &version, &crate_bytes, &orig, &patched).await;
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &cargo_home,
    );
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    assert!(
        read(&proj, "Cargo.toml").contains("socket-patch-"),
        "hosted pin present"
    );

    // B: plain `vendor` over the hosted state — the takeover.
    stage_patch(&proj, &purl, &orig, &patched);
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
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(envelope["summary"]["applied"], 1, "{stdout}");
    // C7: the PLAIN vendor command surfaces the takeover (pre-fix: silent).
    assert!(
        stdout.contains("vendor_takeover_reverted_redirect"),
        "takeover advisory missing from the plain vendor envelope: {stdout}"
    );

    // The project is FULLY vendored: the hosted Cargo.toml pin and the
    // registries block are gone, [patch.crates-io] + detached lock are in,
    // and the hosted ledger record is dropped.
    let toml = read(&proj, "Cargo.toml");
    assert!(
        !toml.contains("socket-patch-"),
        "the hosted registry pin must be reverted (C2 — [patch.crates-io] \
         cannot apply over it and the project is unbuildable): {toml}"
    );
    assert!(
        toml.contains("[patch.crates-io]")
            && toml.contains(&format!(".socket/vendor/cargo/{UUID_V}/")),
        "the vendored wiring lives in Cargo.toml: {toml}"
    );
    let config = read(&proj, ".cargo/config.toml");
    assert!(!config.contains("[patch.crates-io]"), "{config}");
    assert!(
        !config.contains("[registries.socket-patch-"),
        "the now-unused registries block must be dropped: {config}"
    );
    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "the emptied hosted ledger must be removed: {}",
        read(&proj, ".socket/vendor/redirect-state.json")
    );
    let lock_block = package_block(&read(&proj, "Cargo.lock"), DEP).unwrap_or_default();
    assert!(
        !lock_block.contains("source ="),
        "vendored lock entry is detached: {lock_block}"
    );
    assert_lock_version(&proj, &tagged(&version, UUID_V), "hosted -> vendored");

    // C: the vendored contract — fresh checkout, EMPTY home, offline locked
    // build (pre-fix: "no matching package named cfg-if found").
    let (fresh, home) = fresh_checkout(&proj, tmp.path(), "c");
    assert_build_ok(
        "cargo build --locked --offline (vendored fresh checkout)",
        &cargo(&fresh, &["build", "--locked", "--offline"], &home),
    );
    TakeoverVex {
        fresh: fresh.clone(),
        home: home.clone(),
        purl: purl.clone(),
        patched: patched.clone(),
        wired: (UUID_V, Marker::Vendored),
        displaced: UUID_H,
        server_uri: server.uri(),
    }
    .run()
    .await;

    // D: revert restores the PRISTINE pre-hosted project — the crates.io
    // lock fragment (not a dead grant-tokenized sparse URL) and the plain
    // Cargo.toml dep.
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
    assert_eq!(code, 0, "revert failed: {stdout}\n{stderr}");
    assert_eq!(
        std::fs::read(proj.join("Cargo.lock")).unwrap(),
        lock_pristine,
        "Cargo.lock restored byte-identical to the pre-hosted pristine"
    );
    assert_eq!(read(&proj, "Cargo.toml"), toml_pristine);
    assert!(
        !read(&proj, ".cargo/config.toml").contains("[patch.crates-io]")
            && !read(&proj, "Cargo.toml").contains("[patch.crates-io]"),
        "vendored wiring gone after revert"
    );
}

// ── C3: double takeover A→B→A must preserve the crates.io lock originals ────
// vendored → hosted → vendored again: the vendored ledger must carry the
// PRISTINE crates.io source+checksum (pre-fix it silently recorded the hosted
// sparse-index URL + patched checksum as the "originals"), and a final revert
// must restore the byte-identical pristine lock.
#[tokio::test(flavor = "multi_thread")]
async fn double_takeover_a_b_a_preserves_lock_originals() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path()) else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    stage_patch(&proj, &purl, &orig, &patched);
    let toml_pristine = read(&proj, "Cargo.toml");
    let lock_pristine = std::fs::read(proj.join("Cargo.lock")).unwrap();
    // Inline for lock v2+, `[metadata]` for v1.
    let pristine_checksum = cargo_e2e_matrix::parse_lock(&String::from_utf8_lossy(&lock_pristine))
        .into_iter()
        .find(|p| p.name == DEP)
        .and_then(|p| p.checksum)
        .expect("pristine lock has a checksum");

    // A: vendor.
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
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");

    // B: hosted takeover.
    let server = MockServer::start().await;
    let crate_bytes =
        build_patched_crate(&tmp.path().join("stage"), &crate_dir, &version, &patched);
    mount_hosted_mocks(&server, &purl, &version, &crate_bytes, &orig, &patched).await;
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &cargo_home,
    );
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");

    // A again: vendor back.
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
    assert_eq!(code, 0, "re-vendor failed: {stdout}\n{stderr}");

    // The vendored ledger's lock originals are the PRISTINE crates.io values
    // — the only offline-recoverable home of the registry checksum.
    let state: serde_json::Value =
        serde_json::from_str(&read(&proj, ".socket/vendor/state.json")).unwrap();
    let entry = &state["entries"][&purl];
    assert_eq!(
        entry["lock"]["source"], "registry+https://github.com/rust-lang/crates.io-index",
        "C3: the ledger must keep the crates.io source, not the hosted sparse \
         index: {entry}"
    );
    assert_eq!(
        entry["lock"]["checksum"],
        pristine_checksum.as_str(),
        "C3: the ledger must keep the registry tarball checksum: {entry}"
    );

    // The vendored contract still holds after the round trip, and the lock
    // names the vendored patch again (tagged), not the hosted one.
    assert_lock_version(&proj, &tagged(&version, UUID_V), "A -> B -> A");
    let (fresh, home) = fresh_checkout(&proj, tmp.path(), "aba");
    assert_build_ok(
        "cargo build --locked --offline (A->B->A fresh checkout)",
        &cargo(&fresh, &["build", "--locked", "--offline"], &home),
    );
    TakeoverVex {
        fresh: fresh.clone(),
        home: home.clone(),
        purl: purl.clone(),
        patched: patched.clone(),
        wired: (UUID_V, Marker::Vendored),
        displaced: UUID_H,
        server_uri: server.uri(),
    }
    .run()
    .await;

    // Revert: byte-identical pristine lock + Cargo.toml, no residue.
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
    assert_eq!(code, 0, "revert failed: {stdout}\n{stderr}");
    assert_eq!(
        std::fs::read(proj.join("Cargo.lock")).unwrap(),
        lock_pristine,
        "the documented byte-identical pre-vendor Cargo.lock restore (C3)"
    );
    assert_eq!(read(&proj, "Cargo.toml"), toml_pristine);
    let config = read(&proj, ".cargo/config.toml");
    assert!(!config.contains("[patch.crates-io]"), "{config}");
    assert!(
        !proj.join(".cargo").exists(),
        "no .cargo/ residue: {config}"
    );
}

// ── FAIL CLOSED: vendoring over a hosted redirect with no ledger refuses ────
// When the redirect ledger is gone the hosted originals are unrecoverable —
// the vendor run must refuse the purl with an actionable error instead of
// creating the mixed unbuildable state and reporting success.
#[tokio::test(flavor = "multi_thread")]
async fn vendor_over_hosted_without_ledger_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let Some((proj, cargo_home, version, crate_dir)) = stage_fixture(tmp.path()) else {
        return;
    };
    let purl = format!("pkg:cargo/{DEP}@{version}");
    let orig = std::fs::read(crate_dir.join("src/lib.rs")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();

    let server = MockServer::start().await;
    let crate_bytes =
        build_patched_crate(&tmp.path().join("stage"), &crate_dir, &version, &patched);
    mount_hosted_mocks(&server, &purl, &version, &crate_bytes, &orig, &patched).await;
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &cargo_home,
    );
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");

    // The revert data is gone.
    std::fs::remove_file(proj.join(".socket/vendor/redirect-state.json")).unwrap();
    let toml_before = read(&proj, "Cargo.toml");
    let lock_before = read(&proj, "Cargo.lock");

    stage_patch(&proj, &purl, &orig, &patched);
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
    assert_eq!(code, 1, "must fail closed: {stdout}\n{stderr}");
    assert!(
        stdout.contains("hosted_redirect_live"),
        "actionable refusal code missing: {stdout}"
    );
    // Nothing was half-applied: the hosted wiring is untouched and no
    // vendored artifact/wiring was created.
    assert_eq!(read(&proj, "Cargo.toml"), toml_before);
    assert_eq!(read(&proj, "Cargo.lock"), lock_before);
    assert!(!read(&proj, ".cargo/config.toml").contains("[patch.crates-io]"));
    assert!(!read(&proj, "Cargo.toml").contains("[patch.crates-io]"));
    assert!(!vendor_ledger_claims(&proj, &purl));
}
