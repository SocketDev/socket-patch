//! Real-yarn mode-migration e2e: hosted ⇄ vendored takeovers on the npm
//! family must leave the project FULLY in the new mode — or refuse.
//!
//! Twin of `mode_migration_cargo.rs` for the yarn classic + berry lock
//! flavors. Vendoring an npm purl over a LIVE hosted pin must first restore
//! the pin's upstream registry entry (v5: re-resolved from the registry;
//! hosted mode keeps no ledger), or it would:
//!   (a) record the HOSTED patch.socket.dev lock fragment as the vendor
//!       ledger's unrecoverable pre-vendor "original" (not the pristine
//!       registry fragment), and
//!   (b) make `vendor --revert` land back on the (grant-tokenized, expiring)
//!       hosted wiring with no CLI path back to registry state.
//! The reverse direction's hosted state is the lock alone; `rollback`
//! restores its upstream entry.
//!
//! Each scenario drives the REAL binary against a real `corepack yarn`
//! (network used for the registry fixture install only; the hosted patch
//! server is wiremock) and proves the terminal state with a fresh-checkout
//! install plus the marker probe.
//!
//! Skips (println) when `corepack` / the pinned yarn flavor is unavailable or
//! the registry is unreachable for the fixture install; all assertions after
//! that are hard.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "common/hermetic.rs"]
mod hermetic;
// yarn legs: release selection (classic) + the manifest-less VEX matrices.
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "yarn_berry_common/mod.rs"]
mod yarn_berry_common;
#[path = "common/yarn_classic_vex.rs"]
mod yarn_classic_vex;

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

fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    // Scrub FIRST, then the hermetic flags, then per-call env (last wins).
    hermetic::scrub_socket_vars(&mut cmd);
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv, hermetic::Extra::Yarn]);
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
    run_socket_env(cwd, args, &[])
}

/// [`run_socket`] with extra env applied after the scrub.
fn run_socket_env(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = hermetic::command(&binary());
    cmd.current_dir(cwd);
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv, hermetic::Extra::Yarn]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let _fixture = prebuilt_common::prepare_command(&mut cmd, cwd, args, env);
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
    prebuilt_common::mount_download(
        server,
        PURL,
        UUID_V,
        &format!("{DEP}-{DEP_VERSION}.tgz"),
        tgz,
    )
    .await;
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
        let client = reqwest::Client::new();
        let metadata: serde_json::Value = client
            .get(format!("https://registry.npmjs.org/{DEP}/{DEP_VERSION}"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let upstream = client
            .get(metadata["dist"]["tarball"].as_str().unwrap())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let upstream_checksum =
            socket_patch_core::vendor::test_support::service_fixture::berry_checksum(
                &upstream, DEP,
            )
            .unwrap();
        Mock::given(method("GET"))
            .and(path(format!("/upstream/npm/{UUID_H}.json")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": DEP, "version": DEP_VERSION,
                "integrity": sha512_sri(&upstream), "yarnBerry10c0": upstream_checksum
            })))
            .mount(server)
            .await;
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

/// Serve, from `server` (as `SOCKET_NPM_REGISTRY`), the npm registry version
/// document the v5 upstream restore reads for DEP — mirrored from what the
/// PRISTINE classic lock recorded (`resolved "<tarball>#<sha1>"`,
/// `integrity`, or the SHA-1 fragment on pre-1.10 releases). The restore must
/// reproduce the registry entry yarn wrote from that document; mirroring it keeps
/// the unwind hermetic (the binary's TLS stack need not reach the real
/// registry). Returns the registry base and expected upstream lock. Hosted
/// mode adds an integrity line even on pre-1.10 yarn, and v5 restores that
/// line's registry hash without a saved fragment to recover its absence.
async fn mount_registry_from_classic_lock(server: &MockServer, lock: &str) -> (String, String) {
    use base64::Engine as _;

    let block = lock
        .split("\n\n")
        .find(|b| {
            b.contains(&format!("{DEP}@")) && b.contains(&format!("version \"{DEP_VERSION}\""))
        })
        .unwrap_or_else(|| panic!("no {DEP} block in the pristine lock:\n{lock}"));
    let field = |name: &str| {
        block
            .lines()
            .find_map(|l| l.trim().strip_prefix(&format!("{name} ")))
            .map(|v| v.trim_matches('"').to_string())
    };
    let resolved = field("resolved").unwrap_or_else(|| panic!("no `resolved` in {block}"));
    let (tarball, shasum) = resolved
        .split_once('#')
        .map(|(t, s)| (t.to_string(), Some(s.to_string())))
        .unwrap_or((resolved.clone(), None));
    let integrity = field("integrity").unwrap_or_else(|| {
        let sha1 = hex::decode(
            shasum
                .as_ref()
                .expect("pre-1.10 yarn pins a SHA-1 fragment"),
        )
        .expect("the resolved fragment is hex SHA-1");
        format!(
            "sha1-{}",
            base64::engine::general_purpose::STANDARD.encode(sha1)
        )
    });
    let upstream_lock = if field("integrity").is_some() {
        lock.to_string()
    } else {
        lock.replacen(
            &format!("  resolved \"{resolved}\""),
            &format!("  resolved \"{resolved}\"\n  integrity {integrity}"),
            1,
        )
    };
    Mock::given(method("GET"))
        .and(path(format!("/registry/{DEP}/{DEP_VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": DEP,
            "version": DEP_VERSION,
            "dist": { "tarball": tarball, "integrity": integrity, "shasum": shasum }
        })))
        .mount(server)
        .await;
    (format!("{}/registry", server.uri()), upstream_lock)
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
    stage_yarn_fixture_with(tag, pm, berry, &format!(r#""{DEP}":"{DEP_VERSION}""#))
}

/// [`stage_yarn_fixture`] with the root manifest's `dependencies` body
/// spelled out (e.g. a direct dep plus an `npm:` alias of it).
fn stage_yarn_fixture_with(tag: &str, pm: &str, berry: bool, deps: &str) -> Option<YarnFixture> {
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
            r#"{{"name":"mode-migration-npm","version":"0.0.0","private":true,"dependencies":{{{deps}}}}}"#
        ),
    )
    .unwrap();
    let extra_env: Vec<(String, String)> = if berry {
        std::fs::write(
            proj.join(".yarnrc.yml"),
            "nodeLinker: node-modules\nenableGlobalCache: false\n",
        )
        .unwrap();
        let global = tmp.path().join("yarn-global");
        vec![(
            "YARN_GLOBAL_FOLDER".into(),
            global.to_str().unwrap().to_string(),
        )]
    } else {
        let cache = tmp.path().join("yarn-cache");
        vec![(
            "YARN_CACHE_FOLDER".into(),
            cache.to_str().unwrap().to_string(),
        )]
    };
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
    if berry {
        // Windows line endings (yarn writes CRLF there; `EOL_ENV=crlf`
        // reproduces it here): the takeovers must round-trip CRLF files.
        yarn_berry_common::adopt_yarn_line_endings(
            &proj,
            pm,
            &format!("mode-migration-{tag}"),
            &["package.json", "yarn.lock"],
        );
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
/// no hosted ledger exists, the vendor ledger's recorded
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

    // v5 hosted mode keeps no ledger: the lock is the only hosted state,
    // and the takeover's restore removed it.
    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "no hosted ledger may exist ({tag}): {}",
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
    // resolution — not the grant-tokenized hosted values. Classic locks
    // resolve to the registry URL; berry locks to the bare
    // `name@npm:<version>` resolution (no URL).
    let state = read(proj, ".socket/vendor/state.json");
    if berry {
        assert!(
            state.contains(&format!("resolution: \\\"{DEP}@npm:{DEP_VERSION}\\\"")),
            "the vendor ledger must record the registry (npm:) original \
             resolution ({tag}): {state}"
        );
    } else {
        assert!(
            state.contains("registry.yarnpkg.com") || state.contains("registry.npmjs.org"),
            "the vendor ledger must record the registry originals ({tag}): {state}"
        );
    }
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
            &yarn_classic_vex::yarn_classic(),
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

    // (b) Round trip: `vendor --revert` restores the expected REGISTRY lock
    // byte-identically (pre-fix it restored the hosted fragment, with no CLI
    // path back to registry state).
    let (code, stdout, stderr) = run_socket(
        proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "revert failed ({tag}): {stdout}\n{stderr}");
    assert_eq!(
        std::fs::read(proj.join("yarn.lock")).unwrap(),
        lock_pristine,
        "yarn.lock must be restored byte-identical to the expected \
         upstream REGISTRY lock ({tag}); got:\n{}",
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

/// Manifest-less VEX after a classic takeover (yarn classic legs only): a
/// fresh checkout of the terminal state, really installed (`--offline` for
/// vendored — the committed tarball is the only source), then the
/// `ManifestlessVex` matrix for the surviving patch `uuid`. The displaced
/// patch `gone_uuid` must never be attested: the takeover removed its
/// wiring, whatever else survived.
#[allow(clippy::too_many_arguments)]
fn classic_manifestless_vex(
    fx: &YarnFixture,
    tag: &str,
    wiring: yarn_classic_vex::Wiring,
    uuid: &str,
    cve: &str,
    gone_uuid: &str,
    patch_server_url: Option<String>,
    registry_lock: &[u8],
) {
    use yarn_classic_vex::{via_apply, via_vendor, yarn_classic, ManifestlessVex, Wiring};
    let fresh = fresh_checkout(&fx.proj, fx.tmp.path(), tag, false);
    let cache = fx.tmp.path().join(format!("fresh-cache-{tag}"));
    let args: &[&str] = match wiring {
        Wiring::Vendored => &["install", "--frozen-lockfile", "--offline", "--no-progress"],
        Wiring::Hosted => &["install", "--frozen-lockfile", "--no-progress"],
    };
    let ci = corepack(
        &fresh,
        &yarn_classic(),
        args,
        &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
    );
    assert!(
        ci.status.success(),
        "{tag}: fresh-checkout install failed:\n{}",
        String::from_utf8_lossy(&ci.stderr)
    );
    assert_eq!(
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap(),
        fx.patched,
        "{tag}: fresh install must carry the patched bytes"
    );
    let api = vex_e2e_common::PatchApi::start(vec![(
        uuid.to_string(),
        vex_e2e_common::patch_view(
            uuid,
            PURL,
            &[("package/index.js", &git_sha256(&fx.patched))],
            &[(GHSA, &[cve])],
        ),
    )]);
    let m = ManifestlessVex {
        leg: tag,
        wiring,
        purl: PURL,
        uuid,
        vulns: &[(GHSA, &[cve])],
        api: &api,
        proxy_override: None,
        patch_server_url,
        registry_lock: registry_lock.to_vec(),
        reinstall: Some(Box::new(|dir: &Path| {
            std::fs::remove_dir_all(dir.join("node_modules")).expect("rm node_modules");
            let out = corepack(
                dir,
                &yarn_classic(),
                &["install", "--frozen-lockfile", "--no-progress"],
                &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
            );
            assert!(
                out.status.success(),
                "{tag}: reverted-lock install failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                std::fs::read(dir.join("node_modules").join(DEP).join("index.js")).unwrap(),
                fx.orig,
                "{tag}: the reverted lock installs pristine bytes"
            );
        })),
        embedded: match wiring {
            Wiring::Vendored => vec![("apply --vex", via_apply()), ("vendor --vex", via_vendor())],
            Wiring::Hosted => vec![("apply --vex", via_apply())],
        },
    };
    vex_e2e_common::strip_manifest(&fresh);
    let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), &fresh, &m.online());
    assert!(
        !out.stdout.contains(gone_uuid)
            && !out
                .doc
                .as_ref()
                .is_some_and(|d| d.to_string().contains(gone_uuid)),
        "{tag}: the displaced patch must not be attested:\n{out}"
    );
    m.run(&fresh);
}

// ── hosted → vendored takeover, yarn classic ────────────────────────────────
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_hosted_then_vendored_takeover_round_trips_to_registry() {
    let pm = yarn_classic_vex::yarn_classic();
    if !yarn_classic_vex::installs_file_tarballs(&yarn_classic_vex::yarn_classic_version()) {
        println!("N/A classic hosted→vendored: {pm} cannot install vendored `file:` tarballs");
        return;
    }
    let Some(fx) = stage_yarn_fixture("classic", &pm, false) else {
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
    build_patched_tgz(&proj.join("node_modules").join(DEP), &fx.patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    let server = MockServer::start().await;
    let hosted_url = mount_hosted_mocks(&server, &tgz, &fx.orig, &fx.patched, None).await;
    let (code, stdout, stderr) = run_hosted_scan(&proj, &server.uri());
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    let lock = read(&proj, "yarn.lock");
    assert!(lock.contains(&hosted_url), "hosted wiring present:\n{lock}");
    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "hosted mode writes no ledger"
    );

    // B: vendor over the live hosted pin — the takeover. Online: the
    // upstream restore re-resolves the registry entry (mirrored from the
    // pristine lock), and the mock origin is named hosted via
    // --patch-server-url.
    let (registry, lock_upstream) =
        mount_registry_from_classic_lock(&server, &String::from_utf8_lossy(&lock_pristine)).await;
    stage_patch(&proj, &fx.orig, &fx.patched);
    let (code, stdout, stderr) = run_socket_env(
        &proj,
        &[
            "vendor",
            "--json",
            "--patch-server-url",
            server.uri().as_str(),
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &[("SOCKET_NPM_REGISTRY", registry.as_str())],
    );
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(envelope["summary"]["applied"], 1, "{stdout}");

    // Manifest-less VEX of the takeover's terminal (vendored) state.
    tokio::task::block_in_place(|| {
        classic_manifestless_vex(
            &fx,
            "classic-h2v-vex",
            yarn_classic_vex::Wiring::Vendored,
            UUID_V,
            "CVE-2026-99999",
            UUID_H,
            None,
            &lock_pristine,
        )
    });

    assert_pure_vendored_and_round_trip(
        &fx,
        "classic",
        false,
        &hosted_url,
        lock_upstream.as_bytes(),
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
    build_patched_tgz(&proj.join("node_modules").join(DEP), &fx.patched, &tgz_path);
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
        lock.contains(&format!("@{hosted_url}\"")),
        "hosted wiring present:\n{lock}"
    );

    // B: vendor over the live hosted pin — the takeover. Online against the
    // REAL registry: berry's restore re-derives the 10c0 checksum from the
    // registry tarball. The mock origin is named hosted via
    // --patch-server-url.
    stage_patch(&proj, &fx.orig, &fx.patched);
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--patch-server-url",
            server.uri().as_str(),
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(envelope["summary"]["applied"], 1, "{stdout}");

    // MANIFEST-LESS VEX over the post-takeover (pure vendored) state, before
    // the round trip below reverts it: the superseded HOSTED patch (UUID_H,
    // same advisory) must never be attested alongside the vendored one — the
    // matrix's exact-statement-set assertions would see it.
    let tgz_rel = format!(".socket/vendor/npm/{UUID_V}/{DEP}-{DEP_VERSION}.tgz");
    let registry_state = [
        ("yarn.lock", lock_pristine.clone()),
        ("package.json", pkg_json_pristine.clone().into_bytes()),
    ];
    let yarn =
        |cwd: &Path, args: &[&str], env: &[(&str, &str)]| corepack(cwd, YARN_BERRY, args, env);
    let yarnrc = read(&proj, ".yarnrc.yml");
    let flow = yarn_berry_common::BerryVexFlow {
        flow: "hosted-then-vendored-takeover",
        yarn_spec: YARN_BERRY,
        wiring: yarn_berry_common::BerryWiring::Vendored {
            artifact_rel: tgz_rel,
        },
        proj: &proj,
        scratch: fx.tmp.path(),
        committable: &["package.json", "yarn.lock"],
        yarnrc: &yarnrc,
        registry_state: &registry_state,
        purl: PURL,
        uuid: UUID_V,
        vulns: &[(GHSA, &["CVE-2026-99999"])],
        patched: &fx.patched,
        pristine: &fx.orig,
        installed: "node_modules/left-pad/index.js",
        registry_cache: proj.join(".yarn/cache"),
        yarn: &yarn,
        flow_api: None,
        pnp_cell: false,
    };
    yarn_berry_common::off_runtime(|| yarn_berry_common::run_manifestless_vex_matrix(&flow));

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
// redirect — leaving the project purely hosted (the lock is the only hosted
// state), from which `rollback` restores the PRISTINE registry lock.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_vendored_then_hosted_takeover_leaves_pure_hosted() {
    let Some(fx) = stage_yarn_fixture("classic-rev", &yarn_classic_vex::yarn_classic(), false)
    else {
        return;
    };
    let proj = fx.proj.clone();
    let lock_pristine = std::fs::read(proj.join("yarn.lock")).unwrap();

    // A: vendor (offline).
    stage_patch(&proj, &fx.orig, &fx.patched);
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
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    assert!(
        read(&proj, ".socket/vendor/state.json").contains(PURL),
        "vendored ledger claims the purl"
    );

    // B: hosted redirect over the vendored state — the takeover.
    let tgz_path = fx.tmp.path().join("patched.tgz");
    build_patched_tgz(&proj.join("node_modules").join(DEP), &fx.patched, &tgz_path);
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
    // artifact, no `file:` lock residue; the hosted wiring is present and no
    // hosted ledger is written.
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
    assert!(lock.contains(&hosted_url), "lock points hosted:\n{lock}");
    assert!(
        !lock.contains(".socket/vendor/"),
        "no vendored residue in the lock:\n{lock}"
    );
    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "hosted mode writes no ledger"
    );

    // Fresh checkout installs the patched bytes from the hosted tarball.
    let fresh = fresh_checkout(&proj, fx.tmp.path(), "classic-rev", false);
    let fresh_cache = fx.tmp.path().join("fresh-cache-classic-rev");
    let ci = corepack(
        &fresh,
        &yarn_classic_vex::yarn_classic(),
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

    // Manifest-less VEX of the takeover's terminal (hosted) state.
    tokio::task::block_in_place(|| {
        classic_manifestless_vex(
            &fx,
            "classic-v2h-vex",
            yarn_classic_vex::Wiring::Hosted,
            UUID_H,
            "CVE-2026-3333",
            UUID_V,
            Some(server.uri()),
            &lock_pristine,
        )
    });

    // Rollback re-resolves the upstream registry entry. Hosted mode added an
    // integrity line even on pre-1.10 yarn; v5 has no saved fragment to tell
    // whether it was originally absent, so it restores the registry hash.
    let (registry, lock_upstream) =
        mount_registry_from_classic_lock(&server, &String::from_utf8_lossy(&lock_pristine)).await;
    let (code, stdout, stderr) = run_socket_env(
        &proj,
        &[
            "rollback",
            "--json",
            "--yes",
            "--patch-server-url",
            server.uri().as_str(),
            "--cwd",
            proj.to_str().unwrap(),
        ],
        &[("SOCKET_NPM_REGISTRY", registry.as_str())],
    );
    assert_eq!(code, 0, "rollback failed: {stdout}\n{stderr}");
    assert_eq!(
        read(&proj, "yarn.lock"),
        lock_upstream,
        "rollback restores the registry lock, allowing the added upstream integrity"
    );
    let fresh = fresh_checkout(&proj, fx.tmp.path(), "classic-rollback", false);
    let fresh_cache = fx.tmp.path().join("fresh-cache-classic-rollback");
    let ci = corepack(
        &fresh,
        &yarn_classic_vex::yarn_classic(),
        &["install", "--frozen-lockfile", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        ci.status.success(),
        "fresh-checkout rollback install must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    assert_eq!(
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap(),
        fx.orig,
        "rollback installs the pristine registry bytes"
    );
}

// ── yarn classic `npm:` alias copy beside a direct copy (#1081, #1158) ────
// yarn 1.22.22 locks `"lp": "npm:left-pad@1.3.0"` next to a direct
// `left-pad@1.3.0` as two blocks. The hosted rewriter pins the direct block
// and leaves the alias block on the registry
// (`redirect_yarn_classic_alias_skipped`), so the alias copy installs
// unpatched: the run must neither attest that copy nor un-patch a vendored
// one.

/// The direct + `npm:` alias manifest dependencies.
const ALIAS_DEPS: &str = r#""left-pad":"1.3.0","lp":"npm:left-pad@1.3.0""#;

/// [`stage_yarn_fixture_with`] for [`ALIAS_DEPS`] under yarn classic, or
/// `None` (skip) when the release under test merges the alias and direct
/// keys into one block (every release before 1.22.22): that block is
/// pinned whole, and there is no separate alias copy to probe.
fn stage_classic_alias_fixture(tag: &str) -> Option<YarnFixture> {
    let fx = stage_yarn_fixture_with(tag, &yarn_classic_vex::yarn_classic(), false, ALIAS_DEPS)?;
    let lock = read(&fx.proj, "yarn.lock");
    if !lock.lines().any(|l| l.starts_with("\"lp@npm:left-pad@")) {
        println!(
            "N/A {tag}: {} locks the alias in the direct block:\n{lock}",
            yarn_classic_vex::yarn_classic()
        );
        return None;
    }
    Some(fx)
}

/// #1158: a vendored → hosted takeover whose hosted rewrite would pin the
/// direct block but skip the alias block the vendored wiring had patched is
/// retracted: the package stays vendored, byte for byte, and both copies
/// keep installing the patched bytes.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_takeover_keeps_vendored_alias_copy_patched() {
    if !yarn_classic_vex::installs_file_tarballs(&yarn_classic_vex::yarn_classic_version()) {
        println!("N/A classic alias takeover: cannot install vendored `file:` tarballs");
        return;
    }
    let Some(fx) = stage_classic_alias_fixture("classic-alias-takeover") else {
        return;
    };
    let proj = fx.proj.clone();

    stage_patch(&proj, &fx.orig, &fx.patched);
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
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    let lock_vendored = read(&proj, "yarn.lock");
    assert_eq!(
        lock_vendored.matches(".socket/vendor/").count(),
        2,
        "vendoring wires the direct AND the alias block:\n{lock_vendored}"
    );
    let state_vendored = read(&proj, ".socket/vendor/state.json");

    let tgz_path = fx.tmp.path().join("patched.tgz");
    build_patched_tgz(&proj.join("node_modules").join(DEP), &fx.patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    let server = MockServer::start().await;
    mount_hosted_mocks(&server, &tgz, &fx.orig, &fx.patched, None).await;
    let (code, stdout, stderr) = run_hosted_scan(&proj, &server.uri());
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    assert!(
        stdout.contains("redirect_takeover_kept_vendored")
            && stdout.contains("redirect_yarn_classic_alias_skipped"),
        "the takeover is retracted, naming the alias skip: {stdout}"
    );
    assert!(
        !stdout.contains("redirect_takeover_reverted_vendored"),
        "the package must not be announced fully hosted: {stdout}"
    );
    assert_eq!(
        read(&proj, "yarn.lock"),
        lock_vendored,
        "the vendored lock stays byte-identical"
    );
    assert_eq!(
        read(&proj, ".socket/vendor/state.json"),
        state_vendored,
        "the vendored ledger entry is kept"
    );
    assert!(
        proj.join(format!(".socket/vendor/npm/{UUID_V}")).exists(),
        "the committed vendored artifact is kept"
    );

    let fresh = fresh_checkout(&proj, fx.tmp.path(), "classic-alias-takeover", false);
    let fresh_cache = fx.tmp.path().join("fresh-cache-classic-alias-takeover");
    let ci = corepack(
        &fresh,
        &yarn_classic_vex::yarn_classic(),
        &["install", "--frozen-lockfile", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        ci.status.success(),
        "fresh-checkout install must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    for copy in [DEP, "lp"] {
        let installed = std::fs::read(fresh.join("node_modules").join(copy).join("index.js"))
            .unwrap_or_else(|e| panic!("node_modules/{copy}: {e}"));
        assert!(
            installed.starts_with(MARKER.as_bytes()),
            "node_modules/{copy} must stay PATCHED"
        );
    }
}

/// #1081: an in-run `scan --mode hosted --vex` whose rewrite pinned the
/// direct block but skipped the alias block never writes `not_affected` for
/// the package: that copy installs unpatched, as standalone `vex` says.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_hosted_vex_never_attests_over_a_skipped_alias_copy() {
    let Some(fx) = stage_classic_alias_fixture("classic-alias-vex") else {
        return;
    };
    let proj = fx.proj.clone();
    let tgz_path = fx.tmp.path().join("patched.tgz");
    build_patched_tgz(&proj.join("node_modules").join(DEP), &fx.patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    let server = MockServer::start().await;
    let hosted_url = mount_hosted_mocks(&server, &tgz, &fx.orig, &fx.patched, None).await;
    let vex_path = fx.tmp.path().join("in-run.vex.json");
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--vex",
            vex_path.to_str().unwrap(),
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            server.uri().as_str(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    assert!(
        stdout.contains("redirect_yarn_classic_alias_skipped"),
        "the rewrite skips the alias block (exit {code}): {stdout}\n{stderr}"
    );
    let lock = read(&proj, "yarn.lock");
    assert!(lock.contains(&hosted_url), "direct block pinned:\n{lock}");
    let doc = std::fs::read_to_string(&vex_path).unwrap_or_default();
    let attested = serde_json::from_str::<serde_json::Value>(&doc)
        .ok()
        .and_then(|v| v["statements"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .any(|st| {
            st["status"] == "not_affected"
                && st["products"]
                    .as_array()
                    .is_some_and(|ps| ps.iter().any(|p| p.to_string().contains(PURL)))
        });
    assert!(
        !attested,
        "the in-run VEX must not attest {PURL} over the unpatched alias copy \
         (exit {code}):\n{doc}\nstdout: {stdout}"
    );
}

// ── vendored → hosted takeover, yarn berry (reverse direction) ─────────────
// The berry twin of the classic reverse leg: the hosted scan must revert the
// vendored wiring (the root `resolutions` entry AND the `file:` lock entry),
// the ledger entry and the committed artifact FIRST, then redirect. The
// terminal state is proven by a fresh `--immutable --check-cache` install
// from the hosted tarball, then by the manifest-less VEX matrix over it:
// the displaced VENDORED patch (UUID_V) must never be attested.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn berry_vendored_then_hosted_takeover_leaves_pure_hosted() {
    let Some(fx) = stage_yarn_fixture("berry-rev", YARN_BERRY, true) else {
        return;
    };
    let proj = fx.proj.clone();
    let lock_pristine = std::fs::read(proj.join("yarn.lock")).unwrap();
    let pkg_json_pristine = read(&proj, "package.json");

    // A: vendor (offline).
    stage_patch(&proj, &fx.orig, &fx.patched);
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
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    assert!(
        read(&proj, "package.json").contains(".socket/vendor/npm/"),
        "berry vendoring adds the resolutions entry"
    );

    // B: hosted redirect over the vendored state — the takeover.
    let tgz_path = fx.tmp.path().join("patched.tgz");
    build_patched_tgz(&proj.join("node_modules").join(DEP), &fx.patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    let Some(checksum) = bootstrap_berry_checksum(fx.tmp.path(), &tgz_path) else {
        return;
    };
    let server = MockServer::start().await;
    let hosted_url =
        mount_hosted_mocks(&server, &tgz, &fx.orig, &fx.patched, Some(&checksum)).await;
    let (code, stdout, stderr) = run_hosted_scan(&proj, &server.uri());
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(envelope["redirect"]["redirected"], 1, "{stdout}");
    assert!(
        stdout.contains("redirect_takeover_reverted_vendored"),
        "takeover warning missing: {stdout}"
    );

    // Fully hosted: no vendored ledger claim, artifact, resolutions entry or
    // `file:` residue; the lock pins the hosted archive.
    assert!(
        !read(&proj, ".socket/vendor/state.json").contains(PURL),
        "the displaced vendored ledger entry must be dropped"
    );
    assert!(
        !proj.join(format!(".socket/vendor/npm/{UUID_V}")).exists(),
        "the orphaned committed artifact must be removed"
    );
    // The vendored `file:` resolutions entry is reverted; the hosted berry
    // pin routes the same selector to the hosted tarball instead (#465).
    let pkg_json = read(&proj, "package.json");
    assert!(
        !pkg_json.contains(".socket/vendor/") && pkg_json.contains(&hosted_url),
        "the berry resolutions entry is repointed hosted:\n{pkg_json}\npristine:\n{pkg_json_pristine}"
    );
    let lock = read(&proj, "yarn.lock");
    assert!(
        lock.contains(&format!("@{hosted_url}\"")) && lock.contains(&checksum),
        "lock points hosted:\n{lock}"
    );
    assert!(
        !lock.contains(".socket/vendor/"),
        "no vendored residue in the lock:\n{lock}"
    );

    // Fresh checkout installs the patched bytes from the hosted tarball.
    let fresh = fresh_checkout(&proj, fx.tmp.path(), "berry-rev", true);
    let host = server.uri().replace("http://", "");
    let yarnrc = format!(
        "nodeLinker: node-modules\nenableGlobalCache: false\n\
         unsafeHttpWhitelist:\n  - \"{}\"\nnpmRegistryServer: \"http://127.0.0.1:1\"\n",
        host.split(':').next().unwrap_or("127.0.0.1")
    );
    std::fs::write(fresh.join(".yarnrc.yml"), &yarnrc).unwrap();
    let fresh_global = fx.tmp.path().join("fresh-global-berry-rev");
    let ci = corepack(
        &fresh,
        YARN_BERRY,
        &["install", "--immutable", "--check-cache"],
        &[("YARN_GLOBAL_FOLDER", fresh_global.to_str().unwrap())],
    );
    assert!(
        ci.status.success(),
        "fresh-checkout hosted install must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert_eq!(
        installed, fx.patched,
        "hosted install must carry the PATCHED bytes"
    );

    // MANIFEST-LESS VEX over the pure hosted state (see yarn_berry_common).
    // The hosted berry pin routes `resolutions` too (#465), so the registry
    // state restores the manifest as well as the lock.
    let registry_state = [
        ("yarn.lock", lock_pristine),
        ("package.json", pkg_json_pristine.clone().into_bytes()),
    ];
    let yarn =
        |cwd: &Path, args: &[&str], env: &[(&str, &str)]| corepack(cwd, YARN_BERRY, args, env);
    let api_url = server.uri();
    let flow = yarn_berry_common::BerryVexFlow {
        flow: "vendored-then-hosted-takeover",
        yarn_spec: YARN_BERRY,
        wiring: yarn_berry_common::BerryWiring::Hosted {
            patch_server: api_url.clone(),
        },
        proj: &proj,
        scratch: fx.tmp.path(),
        committable: &["package.json", "yarn.lock"],
        yarnrc: &yarnrc,
        registry_state: &registry_state,
        purl: PURL,
        uuid: UUID_H,
        vulns: &[(GHSA, &["CVE-2026-3333"])],
        patched: &fx.patched,
        pristine: &fx.orig,
        installed: "node_modules/left-pad/index.js",
        registry_cache: proj.join(".yarn/cache"),
        yarn: &yarn,
        flow_api: Some(yarn_berry_common::FlowApi {
            api_url,
            org: ORG.to_string(),
        }),
        pnp_cell: false,
    };
    yarn_berry_common::off_runtime(|| yarn_berry_common::run_manifestless_vex_matrix(&flow));
}
