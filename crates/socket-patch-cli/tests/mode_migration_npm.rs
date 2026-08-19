//! Real-yarn mode-migration e2e: hosted ⇄ vendored takeovers on the npm
//! family must leave the project FULLY in the new mode — or refuse.
//!
//! Twin of `mode_migration_cargo.rs` (the file that pins the C1–C7 cargo
//! takeover bug class from #196) for the yarn classic + berry lock flavors.
//! Pre-fix, the vendor dispatch loop's cross-mode pre-revert was hard-gated
//! `candidate.starts_with("pkg:cargo/")`, so vendoring an npm purl over a
//! LIVE hosted redirect:
//!   (a) recorded the HOSTED patch.socket.dev lock fragment as the vendor
//!       ledger's unrecoverable pre-vendor "original" (not the pristine
//!       registry fragment),
//!   (b) left the redirect ledger's records + edits in place forever, so the
//!       `vendor_supersedes_redirect` warning's promised auto-reconcile never
//!       converged, and
//!   (c) made `vendor --revert` land back on the (grant-tokenized, expiring)
//!       hosted wiring with no CLI path back to registry state.
//!
//! Each scenario drives the REAL binary against a real `corepack yarn`
//! (network used for the registry fixture install only; the hosted patch
//! server is wiremock) and proves the terminal state with a fresh-checkout
//! install plus the marker probe.
//!
//! Skips (println) when `corepack` / the pinned yarn flavor is unavailable or
//! the registry is unreachable for the fixture install; all assertions after
//! that are hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
/// Vendored patch uuid (the `.socket/vendor/npm/<uuid>/` path level).
const UUID_V: &str = "3c4d5e6f-7a8b-4c1d-8e2f-0123456789ab";
/// Hosted patch uuid (embedded in the hosted artifact URL).
const UUID_H: &str = "8d9e0f1a-2b3c-4d4e-8f5a-6b7c8d9e0f1a";
const TOKEN: &str = "44444444-4444-4444-8444-444444444444";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const GHSA: &str = "GHSA-migr-npm-test";
const YARN_CLASSIC: &str = "yarn@1.22.22";
const YARN_BERRY: &str = "yarn@4.12.0";

// ── self-contained helpers (harness patterns shared with the redirect /
//    vendor yarn capstones) ──────────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Probe corepack from a NEUTRAL temp dir: a `packageManager` field in an
/// ancestor `package.json` makes corepack refuse to run a different package
/// manager, which would spuriously fail the gate.
fn has_corepack_pm(pm: &str) -> bool {
    let Ok(probe) = tempfile::tempdir() else {
        return false;
    };
    let mut cmd = Command::new("corepack");
    cmd.args([pm, "--version"])
        .current_dir(probe.path())
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    cache_env::isolate(&mut cmd);
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Remove ambient `SOCKET_*` (except the hermetic `SOCKET_NO_CONFIG`) and
/// every `YARN_*` var. Seed-then-scrub for `YARN_NODE_LINKER` (mirrors
/// `e2e_redirect_yarn_berry_build.rs`): berry lets any yarnrc setting be
/// overridden by env, so an ambient `YARN_NODE_LINKER=pnp` would silently
/// build a PnP tree and void the node_modules probes.
fn scrub_socket_env(cmd: &mut Command) {
    cmd.env("YARN_NODE_LINKER", "pnp");
    for (k, _) in std::env::vars_os() {
        let key = k.to_string_lossy();
        if (key.starts_with("SOCKET_") || key.starts_with("YARN_")) && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("YARN_NODE_LINKER");
}

fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    // Scrub FIRST, then the hermetic flags, then per-call env (last wins).
    scrub_socket_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        // No global mirror/cache: the fresh-checkout legs must not be able to
        // reuse archives another leg parked in `~/.yarn/berry`.
        .env("YARN_ENABLE_GLOBAL_CACHE", "false");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run corepack")
}

fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    scrub_socket_env(&mut cmd);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
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

fn git_sha256(content: &[u8]) -> String {
    compute_git_sha256_from_bytes(content)
}

/// Write `.socket/manifest.json` + the after-hash blob so `vendor --offline`
/// runs fully offline (npm-family file keys carry the `package/` prefix).
fn stage_patch(proj: &Path, before: &[u8], after: &[u8]) {
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": { PURL: {
            "uuid": UUID_V,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": git_sha256(before),
                "afterHash": git_sha256(after),
            }},
            "vulnerabilities": { GHSA: {
                "cves": ["CVE-2026-99999"],
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

/// Build a patched npm tarball (`package/` prefix, marker-prepended index.js)
/// from the installed dep directory. Built in-process with ONLY regular-file
/// entries — yarn classic rejects the directory/AppleDouble entries a system
/// `tar -czf` emits.
fn build_patched_tgz(installed_dir: &Path, patched_index: &[u8], out_tgz: &Path) {
    fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let ft = entry.file_type().unwrap();
            if ft.is_dir() {
                collect_files(root, &entry.path(), out);
            } else if ft.is_file() {
                out.push(entry.path().strip_prefix(root).unwrap().to_path_buf());
            }
        }
    }
    let mut files = Vec::new();
    collect_files(installed_dir, installed_dir, &mut files);
    files.sort();

    let gz = flate2::write::GzEncoder::new(
        std::fs::File::create(out_tgz).unwrap(),
        flate2::Compression::default(),
    );
    let mut builder = tar::Builder::new(gz);
    for rel in files {
        let bytes = if rel == Path::new("index.js") {
            patched_index.to_vec()
        } else {
            std::fs::read(installed_dir.join(&rel)).unwrap()
        };
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        let entry_path = Path::new("package").join(&rel);
        builder
            .append_data(&mut header, entry_path, bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap();
}

/// Hex sha1 of `bytes` — the `resolved "…#<sha1>"` fragment yarn classic
/// verifies against the fetched tarball.
fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::Digest as _;
    hex::encode(sha1::Sha1::digest(bytes))
}

/// `sha512-<b64>` SRI of `bytes` — the classic `integrity` line.
fn sha512_sri(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
    )
}

/// BOOTSTRAP (berry only): resolve the patched tarball with a real yarn
/// (`resolutions` pointing at `file:./patched.tgz`) so yarn writes the exact
/// `checksum: 10c0/<hex>` for that tarball's cache zip — the value the hosted
/// mock must hand back. `None` if the bootstrap install could not run.
fn bootstrap_berry_checksum(tmp: &Path, patched_tgz: &Path) -> Option<String> {
    let boot = tmp.join("berry-bootstrap");
    std::fs::create_dir_all(&boot).unwrap();
    std::fs::copy(patched_tgz, boot.join("patched.tgz")).unwrap();
    std::fs::write(
        boot.join("package.json"),
        format!(
            r#"{{"name":"berry-bootstrap","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}},"resolutions":{{"{DEP}":"file:./patched.tgz"}}}}"#
        ),
    )
    .unwrap();
    std::fs::write(
        boot.join(".yarnrc.yml"),
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    )
    .unwrap();
    let global = tmp.join("berry-bootstrap-global");
    let out = corepack(
        &boot,
        YARN_BERRY,
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !out.status.success() {
        println!(
            "SKIP mode_migration_npm: bootstrap yarn install failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    let lock = std::fs::read_to_string(boot.join("yarn.lock")).ok()?;
    let checksum = lock
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("checksum: 10c0/"))?
        .trim_start_matches("checksum: ")
        .to_string();
    Some(checksum)
}

/// Mount the full hosted-mode mock set (discovery + reference + view +
/// download) for patch UUID_H over PURL. `berry_checksum` adds the
/// `yarn-berry-zip` artifact the berry rewriter requires. Returns the hosted
/// tarball URL.
async fn mount_hosted_mocks(
    server: &MockServer,
    tgz: &[u8],
    orig: &[u8],
    patched: &[u8],
    berry_checksum: Option<&str>,
) -> String {
    let hosted_url = format!(
        "{}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID_H}/{DEP}-{DEP_VERSION}.tgz",
        server.uri()
    );
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID_H, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "npm migration fixture"
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
                "uuid": UUID_H, "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    let mut artifacts = vec![serde_json::json!({
        "kind": "tarball", "url": hosted_url,
        "integrity": { "sha512": sha512_sri(tgz), "sha1": sha1_hex(tgz) }
    })];
    if let Some(checksum) = berry_checksum {
        artifacts.push(serde_json::json!({
            "kind": "yarn-berry-zip", "url": hosted_url,
            "integrity": { "yarnBerry10c0": checksum }
        }));
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID_H: {
                    "status": "granted",
                    "url": hosted_url,
                    "purl": PURL,
                    "artifacts": artifacts,
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID_H}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID_H,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": compute_git_sha256_from_bytes(orig),
                    "afterHash": compute_git_sha256_from_bytes(patched),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-3333"],
                    "summary": "migration vuln", "severity": "high", "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID_H}/{DEP}-{DEP_VERSION}.tgz"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(tgz.to_vec(), "application/octet-stream"),
        )
        .mount(server)
        .await;
    hosted_url
}

fn run_hosted_scan(proj: &Path, server_uri: &str) -> (i32, String, String) {
    run_socket(
        proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            server_uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    )
}

fn read(proj: &Path, rel: &str) -> String {
    std::fs::read_to_string(proj.join(rel)).unwrap_or_default()
}

/// The classic/berry fixture project after a REAL `corepack yarn install`.
struct YarnFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    orig: Vec<u8>,
    patched: Vec<u8>,
}

/// package.json + (berry: .yarnrc.yml) + real install. `None` = skip.
fn stage_yarn_fixture(tag: &str, pm: &str, berry: bool) -> Option<YarnFixture> {
    if !has_corepack_pm(pm) {
        println!("SKIP mode_migration_npm ({tag}): `corepack {pm}` unavailable");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"mode-migration-npm","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();
    let extra_env: Vec<(String, String)>;
    if berry {
        std::fs::write(
            proj.join(".yarnrc.yml"),
            "nodeLinker: node-modules\nenableGlobalCache: false\n",
        )
        .unwrap();
        let global = tmp.path().join("yarn-global");
        extra_env = vec![(
            "YARN_GLOBAL_FOLDER".into(),
            global.to_str().unwrap().to_string(),
        )];
    } else {
        let cache = tmp.path().join("yarn-cache");
        extra_env = vec![(
            "YARN_CACHE_FOLDER".into(),
            cache.to_str().unwrap().to_string(),
        )];
    }
    let env_refs: Vec<(&str, &str)> = extra_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let args: &[&str] = if berry {
        &["install"]
    } else {
        &["install", "--no-progress"]
    };
    let install = corepack(&proj, pm, args, &env_refs);
    if !install.status.success() {
        println!(
            "SKIP mode_migration_npm ({tag}): fixture `yarn install` failed (registry \
             unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return None;
    }
    let orig = std::fs::read(proj.join("node_modules").join(DEP).join("index.js"))
        .expect("installed index.js");
    assert!(
        !orig.starts_with(MARKER.as_bytes()),
        "pristine install must not carry the marker"
    );
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    Some(YarnFixture {
        tmp,
        proj,
        orig,
        patched,
    })
}

/// Copy ONLY the committable files to a fresh dir (the fresh-checkout proof).
fn fresh_checkout(proj: &Path, tmp: &Path, tag: &str, berry: bool) -> PathBuf {
    let fresh = tmp.join(format!("fresh-{tag}"));
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    if berry {
        std::fs::copy(proj.join(".yarnrc.yml"), fresh.join(".yarnrc.yml")).unwrap();
    }
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    fresh
}

/// Assertions shared by the classic and berry hosted→vendored legs:
/// the redirect ledger is fully reconciled, the vendor ledger's recorded
/// originals are the PRISTINE registry fragments, a fresh checkout installs
/// the patched bytes, and `vendor --revert` restores the registry lock
/// byte-identically.
fn assert_pure_vendored_and_round_trip(
    fx: &YarnFixture,
    tag: &str,
    berry: bool,
    hosted_url: &str,
    lock_pristine: &[u8],
    pkg_json_pristine: &str,
    vendor_stdout: &str,
) {
    let proj = &fx.proj;

    // The takeover is surfaced on the vendor envelope (C7 twin).
    assert!(
        vendor_stdout.contains("vendor_takeover_reverted_redirect"),
        "takeover advisory missing from the vendor envelope ({tag}): {vendor_stdout}"
    );

    // (b) The superseded redirect ledger is DROPPED — records and edits both
    // — so the vendor_supersedes_redirect warning can never fire again and
    // no stale hosted originals survive as a revert replay hazard.
    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "the emptied redirect ledger must be removed ({tag}): {}",
        read(proj, ".socket/vendor/redirect-state.json")
    );

    // The lock is FULLY vendored: no hosted URL residue.
    let lock = read(proj, "yarn.lock");
    assert!(
        !lock.contains(hosted_url) && !lock.contains("__archiveUrl"),
        "the hosted wiring must be gone from yarn.lock ({tag}):\n{lock}"
    );
    assert!(
        lock.contains(".socket/vendor/npm/"),
        "the vendored wiring must be present ({tag}):\n{lock}"
    );

    // (a) The vendor ledger's recorded lock originals are the PRISTINE
    // registry fragments — the only offline-recoverable home of the registry
    // resolution — not the grant-tokenized hosted values.
    let state = read(proj, ".socket/vendor/state.json");
    assert!(
        state.contains("registry.yarnpkg.com") || state.contains("registry.npmjs.org"),
        "the vendor ledger must record the registry originals ({tag}): {state}"
    );
    assert!(
        !state.contains("/patch/npm/") && !state.contains("__archiveUrl"),
        "the vendor ledger must NOT record the hosted fragment as its \
         original ({tag}): {state}"
    );

    // Fresh checkout installs the PATCHED bytes from the committed artifact.
    let fresh = fresh_checkout(proj, fx.tmp.path(), tag, berry);
    let ci = if berry {
        let fresh_global = fx.tmp.path().join(format!("fresh-global-{tag}"));
        corepack(
            &fresh,
            YARN_BERRY,
            &["install", "--immutable", "--check-cache"],
            &[("YARN_GLOBAL_FOLDER", fresh_global.to_str().unwrap())],
        )
    } else {
        let fresh_cache = fx.tmp.path().join(format!("fresh-cache-{tag}"));
        corepack(
            &fresh,
            YARN_CLASSIC,
            &["install", "--frozen-lockfile", "--offline", "--no-progress"],
            &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
        )
    };
    assert!(
        ci.status.success(),
        "fresh-checkout vendored install must succeed ({tag}).\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "fresh vendored install must carry the PATCHED bytes ({tag})"
    );

    // (c) Round trip: `vendor --revert` restores the REGISTRY lock
    // byte-identically (pre-fix it restored the hosted fragment, with no CLI
    // path back to registry state).
    let (code, stdout, stderr) = run_socket(
        proj,
        &["vendor", "--revert", "--json", "--cwd", proj.to_str().unwrap()],
    );
    assert_eq!(code, 0, "revert failed ({tag}): {stdout}\n{stderr}");
    assert_eq!(
        std::fs::read(proj.join("yarn.lock")).unwrap(),
        lock_pristine,
        "yarn.lock must be restored byte-identical to the pre-hosted \
         REGISTRY pristine ({tag}); got:\n{}",
        read(proj, "yarn.lock")
    );
    assert_eq!(
        read(proj, "package.json"),
        pkg_json_pristine,
        "package.json restored ({tag})"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert ({tag})"
    );
}

// ── hosted → vendored takeover, yarn classic ────────────────────────────────
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_hosted_then_vendored_takeover_round_trips_to_registry() {
    let Some(fx) = stage_yarn_fixture("classic", YARN_CLASSIC, false) else {
        return;
    };
    let proj = fx.proj.clone();
    let lock_pristine = std::fs::read(proj.join("yarn.lock")).unwrap();
    let pkg_json_pristine = read(&proj, "package.json");
    assert!(
        String::from_utf8_lossy(&lock_pristine).contains("# yarn lockfile v1"),
        "fixture must be a classic v1 lock"
    );

    // A: hosted redirect.
    let tgz_path = fx.tmp.path().join("patched.tgz");
    build_patched_tgz(
        &proj.join("node_modules").join(DEP),
        &fx.patched,
        &tgz_path,
    );
    let tgz = std::fs::read(&tgz_path).unwrap();
    let server = MockServer::start().await;
    let hosted_url = mount_hosted_mocks(&server, &tgz, &fx.orig, &fx.patched, None).await;
    let (code, stdout, stderr) = run_hosted_scan(&proj, &server.uri());
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    let lock = read(&proj, "yarn.lock");
    assert!(
        lock.contains(&hosted_url),
        "hosted wiring present:\n{lock}"
    );
    assert!(
        proj.join(".socket/vendor/redirect-state.json").exists(),
        "hosted ledger written"
    );

    // B: vendor over the live hosted redirect — the takeover.
    stage_patch(&proj, &fx.orig, &fx.patched);
    let (code, stdout, stderr) = run_socket(
        &proj,
        &["vendor", "--json", "--offline", "--cwd", proj.to_str().unwrap()],
    );
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(envelope["summary"]["applied"], 1, "{stdout}");

    assert_pure_vendored_and_round_trip(
        &fx,
        "classic",
        false,
        &hosted_url,
        &lock_pristine,
        &pkg_json_pristine,
        &stdout,
    );
}

// ── hosted → vendored takeover, yarn berry (E5 twin) ────────────────────────
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn berry_hosted_then_vendored_takeover_round_trips_to_registry() {
    let Some(fx) = stage_yarn_fixture("berry", YARN_BERRY, true) else {
        return;
    };
    let proj = fx.proj.clone();
    let lock_pristine = std::fs::read(proj.join("yarn.lock")).unwrap();
    let pkg_json_pristine = read(&proj, "package.json");

    // A: hosted redirect (berry needs the bootstrap-resolved 10c0 checksum).
    let tgz_path = fx.tmp.path().join("patched.tgz");
    build_patched_tgz(
        &proj.join("node_modules").join(DEP),
        &fx.patched,
        &tgz_path,
    );
    let tgz = std::fs::read(&tgz_path).unwrap();
    let Some(checksum) = bootstrap_berry_checksum(fx.tmp.path(), &tgz_path) else {
        return;
    };
    let server = MockServer::start().await;
    let hosted_url =
        mount_hosted_mocks(&server, &tgz, &fx.orig, &fx.patched, Some(&checksum)).await;
    let (code, stdout, stderr) = run_hosted_scan(&proj, &server.uri());
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    let lock = read(&proj, "yarn.lock");
    assert!(
        lock.contains("::__archiveUrl="),
        "hosted wiring present:\n{lock}"
    );

    // B: vendor over the live hosted redirect — the takeover.
    stage_patch(&proj, &fx.orig, &fx.patched);
    let (code, stdout, stderr) = run_socket(
        &proj,
        &["vendor", "--json", "--offline", "--cwd", proj.to_str().unwrap()],
    );
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(envelope["summary"]["applied"], 1, "{stdout}");

    assert_pure_vendored_and_round_trip(
        &fx,
        "berry",
        true,
        &hosted_url,
        &lock_pristine,
        &pkg_json_pristine,
        &stdout,
    );
}

// ── vendored → hosted takeover, yarn classic (reverse direction) ────────────
// The hosted scan must revert the vendored wiring + ledger entry + committed
// artifact FIRST (per purl, the exact `vendor --revert` machinery), then
// redirect — leaving the project purely hosted with the redirect ledger's
// originals recording the PRISTINE registry fragments.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_vendored_then_hosted_takeover_leaves_pure_hosted() {
    let Some(fx) = stage_yarn_fixture("classic-rev", YARN_CLASSIC, false) else {
        return;
    };
    let proj = fx.proj.clone();

    // A: vendor (offline).
    stage_patch(&proj, &fx.orig, &fx.patched);
    let (code, stdout, stderr) = run_socket(
        &proj,
        &["vendor", "--json", "--offline", "--cwd", proj.to_str().unwrap()],
    );
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    assert!(
        read(&proj, ".socket/vendor/state.json").contains(PURL),
        "vendored ledger claims the purl"
    );

    // B: hosted redirect over the vendored state — the takeover.
    let tgz_path = fx.tmp.path().join("patched.tgz");
    build_patched_tgz(
        &proj.join("node_modules").join(DEP),
        &fx.patched,
        &tgz_path,
    );
    let tgz = std::fs::read(&tgz_path).unwrap();
    let server = MockServer::start().await;
    let hosted_url = mount_hosted_mocks(&server, &tgz, &fx.orig, &fx.patched, None).await;
    let (code, stdout, stderr) = run_hosted_scan(&proj, &server.uri());
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(envelope["redirect"]["redirected"], 1, "{stdout}");
    assert!(
        stdout.contains("redirect_takeover_reverted_vendored"),
        "takeover warning missing: {stdout}"
    );

    // The project is FULLY hosted: no vendored ledger claim, no committed
    // artifact, no `file:` lock residue; the hosted wiring is present and its
    // ledger records the PRISTINE registry originals.
    assert!(
        !read(&proj, ".socket/vendor/state.json").contains(PURL),
        "the displaced vendored ledger entry must be dropped: {}",
        read(&proj, ".socket/vendor/state.json")
    );
    assert!(
        !proj.join(format!(".socket/vendor/npm/{UUID_V}")).exists(),
        "the orphaned committed artifact must be removed"
    );
    let lock = read(&proj, "yarn.lock");
    assert!(
        lock.contains(&hosted_url),
        "lock points hosted:\n{lock}"
    );
    assert!(
        !lock.contains(".socket/vendor/"),
        "no vendored residue in the lock:\n{lock}"
    );
    let ledger = read(&proj, ".socket/vendor/redirect-state.json");
    assert!(
        ledger.contains("registry.yarnpkg.com") || ledger.contains("registry.npmjs.org"),
        "the redirect ledger's originals must be the pristine registry \
         fragments (originals chain intact across migrations): {ledger}"
    );

    // Fresh checkout installs the patched bytes from the hosted tarball.
    let fresh = fresh_checkout(&proj, fx.tmp.path(), "classic-rev", false);
    let fresh_cache = fx.tmp.path().join("fresh-cache-classic-rev");
    let ci = corepack(
        &fresh,
        YARN_CLASSIC,
        &["install", "--frozen-lockfile", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        ci.status.success(),
        "fresh-checkout hosted install must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "hosted install must carry the PATCHED bytes"
    );
}
