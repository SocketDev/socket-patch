//! Real-bun redirect capstone e2e — the hosted-mode full-chain proof for the
//! bun (text `bun.lock`) flavor, mirroring `e2e_redirect_npm_build.rs`.
//!
//! `scan --mode hosted` rewrites `bun.lock` so the patched dependency's
//! `packages` entry moves from the registry 4-tuple to the URL 3-tuple
//! `["<name>@<hosted-url>", {deps}, "sha512-<patched>"]`, and records the
//! patch in the redirect ledger. This test proves every link against REAL
//! `bun`:
//!
//!   1. `bun install` of left-pad@1.3.0 (network for fixture setup only,
//!      private `BUN_INSTALL_CACHE_DIR`). The text `bun.lock` is the default
//!      from bun 1.2.0 (lockfileVersion 1; 2 from 1.4.0); on 1.1.39–1.1.x it
//!      is the `--save-text-lockfile` opt-in (lockfileVersion 0), which the
//!      fixture passes for those releases, and the fixture ASSERTS the
//!      version it got matches that era table. Bun before 1.1.39 has no
//!      text lockfile and the suite skips (or, under the REQUIRED gate,
//!      fails — such a leg must not be scheduled). The registry 4-tuple
//!      spelling is identical across 0/1/2, so everything after the
//!      fixture guard is version-independent.
//!   2. Build a PATCHED tarball from the installed bytes (tar crate — no
//!      system `tar`, so Windows runners need nothing); its sha512 is what
//!      the redirect mock hands back (bun verifies the downloaded tarball's
//!      sha512 directly — no cache-zip conversion like yarn berry, so no
//!      bootstrap is needed).
//!   3. `scan --mode hosted --json --vex` (the real binary): bun.lock now
//!      pins the hosted URL + the patched sha512 and keeps its own
//!      lockfileVersion line, the ledger embeds the record, the in-run VEX
//!      is the `(redirected)` attestation.
//!   4. FRESH-CHECKOUT PROOF: only package.json + bun.lock + .socket/ travel;
//!      `bun install --frozen-lockfile` with a fresh `BUN_INSTALL_CACHE_DIR`
//!      MUST install the patched bytes from the hosted tarball. Then the
//!      ORDINARY install (`node_modules` removed, another empty cache, plain
//!      `bun install`) MUST leave bun.lock byte-identical — frozen mode
//!      never writes the lock, so only a plain install can observe bun
//!      re-serializing the URL tuple (the backtest's `ordinaryStableLock`
//!      is the matrix twin) — and land the marker bytes again.
//!
//! The rollback leg continues from step 4: `rollback --yes` must restore
//! bun.lock byte-for-byte to the pre-redirect snapshot, delete the redirect
//! ledger, and a fresh frozen install of the restored lock must produce the
//! ORIGINAL registry bytes (marker gone).
//!
//! The negative twin serves TAMPERED tarball bytes (a different, valid
//! tarball) while the lock keeps the real sha512. Bun verifies URL-tarball
//! digests only from 1.3.10 (`Integrity check failed`): there the fresh
//! frozen install MUST fail, and on every older text-lock bun it MUST
//! succeed and install the tampered bytes (reported PARTIAL) — the boundary
//! is pinned from both sides as [`TARBALL_INTEGRITY_ENFORCED_FROM`]. The
//! vendored twin lives in `e2e_vendor_bun_build.rs`.
//!
//! The get-driven twin (v3.6) runs step 3 as `get <uuid> --mode hosted`
//! instead of `scan --mode hosted` — same hosted engine by construction
//! (get routes through scan's `run_redirect_selected`), so the lock/ledger
//! assertions and the fresh-checkout proof are shared via [`HostedDriver`].
//!
//! The lock-v1-on-newer-bun leg is the one cross-version install proof a
//! single binary can give: on bun ≥ 1.4 (native lockfileVersion 2) the
//! fixture lock is relabelled to `"lockfileVersion": 1` before the rewrite
//! (the lock a 1.3.x bun wrote — grammar-identical, `configVersion` kept),
//! because bun 1.4 reads such a lock and never bumps it in place, so an
//! upgraded team keeps installing the redirect from their committed v1
//! lock. (The former forced-v2 leg proved nothing distinct: on ≥ 1.4 it
//! was the native lock, below 1.4 unreadable.)
//!
//! `bun.lockb` (bun's legacy binary lockfile) auto-migration is NOT exercised
//! here: every bun ≥ 1.2 writes the text `bun.lock` by default and offers no
//! flag to emit the binary form, so a real lockb fixture cannot be generated
//! on the toolchains this suite is wired to. That branch is covered by the
//! in-process shim tests `scan_redirect_migrates_bun_lockb_then_redirects`
//! and siblings in `tests/in_process_redirect.rs`, and against real bun
//! 1.1.45 (lockb by default, migration-capable) by the bun-compatibility
//! native matrix (`scripts/backtest-bun.py`).
//!
//! Gates: without `SOCKET_PATCH_BUN_E2E_REQUIRED` (set AND non-empty — CI
//! passes an empty string for non-bun legs) a missing `bun`, a failed
//! fixture install or a bun without a text lockfile is a `println` SKIP and
//! every assertion after that is HARD. With it, those skips become hard
//! failures, and `SOCKET_PATCH_BUN_E2E_VERSION` (when set, non-empty) must
//! equal `bun --version`, so a CI leg cannot pass by running the wrong bun
//! or no bun at all.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d";
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
/// Content of the tampered twin's served tarball — distinct from the
/// pristine AND the patched bytes so "bun installed the tampered bytes" is
/// a real assertion, not a trailing-byte no-op.
const TAMPER_MARKER: &str = "/* SOCKET-TAMPERED */\n";
const GHSA: &str = "GHSA-redirect-bun-real";
const PRODUCT: &str = "pkg:npm/app@1.0.0";

/// `(major, minor, patch)` of the bun on PATH.
type BunVersion = (u64, u64, u64);

/// First bun that verifies the sha512 of URL / local-tarball tuples on
/// install (1.3.9 installs a mismatched tarball with exit 0; 1.3.10 fails
/// with `Integrity check failed`). NOT 1.3.14 — that figure came from a
/// matrix that sampled only 1.3.0 and 1.3.14. Registry 4-tuples are
/// verified from 1.2.0 and are not what the hosted rewrite produces.
const TARBALL_INTEGRITY_ENFORCED_FROM: BunVersion = (1, 3, 10);
/// First bun with a text lockfile (`--save-text-lockfile` opt-in,
/// lockfileVersion 0). Older bun writes only the binary `bun.lockb`.
const TEXT_LOCK_FROM: BunVersion = (1, 1, 39);
/// Text lock becomes the default and bumps to lockfileVersion 1.
const LOCK_V1_FROM: BunVersion = (1, 2, 0);
/// lockfileVersion 2.
const LOCK_V2_FROM: BunVersion = (1, 4, 0);

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// The REQUIRED gate: set AND non-empty. CI's e2e matrix passes
/// `SOCKET_PATCH_BUN_E2E_REQUIRED: ${{ matrix.bun != '' && '1' || '' }}`,
/// so an empty value is the non-bun legs' "unset" — an `is_some()` gate
/// would turn every non-bun leg red.
fn bun_required() -> bool {
    std::env::var_os("SOCKET_PATCH_BUN_E2E_REQUIRED").is_some_and(|v| !v.is_empty())
}

/// The exact bun the matrix leg pinned, when it pinned one.
fn pinned_bun_version() -> Option<String> {
    std::env::var("SOCKET_PATCH_BUN_E2E_VERSION")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// `1.4.2` → `(1, 4, 2)`; a canary suffix (`1.4.3-canary.12+abc`) is cut at
/// the first `-`/`+`. `None` for anything that is not three integers.
fn parse_bun_version(raw: &str) -> Option<BunVersion> {
    let core = raw.trim().split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// `bun --version` through the cache sandbox: `Some(trimmed stdout)` when
/// bun ran and exited 0, `None` when it is not on PATH (or cannot start).
fn bun_version_output() -> Option<String> {
    let mut probe = Command::new("bun");
    probe.arg("--version");
    scrub_socket_env(&mut probe);
    cache_env::isolate(&mut probe);
    let out = probe.stderr(Stdio::null()).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The lockfileVersion the era table says this bun writes for a FRESH
/// install: 1.1.39–1.1.x opt-in text lock → 0, 1.2–1.3 → 1, ≥ 1.4 → 2.
fn expected_lock_version(v: BunVersion) -> u64 {
    if v >= LOCK_V2_FROM {
        2
    } else if v >= LOCK_V1_FROM {
        1
    } else {
        0
    }
}

/// The fixture's `bun install` argv: lifecycle scripts never run (hygiene —
/// left-pad has none, but the fixture is a REAL registry install), and
/// `--save-text-lockfile` is passed only where the text lock is still an
/// opt-in (< 1.2.0), so newer bun is exercised exactly as users run it.
fn fixture_install_args(v: BunVersion) -> Vec<&'static str> {
    let mut args = vec!["install", "--ignore-scripts"];
    if v < LOCK_V1_FROM {
        args.push("--save-text-lockfile");
    }
    args
}

/// `"lockfileVersion": <n>` from the lock head — the same head scan as
/// `socket_patch_core::vendor::bun_lock_text::lock_version` (pub(crate)
/// there, so mirrored here).
fn lock_version(text: &str) -> Option<u64> {
    text.lines()
        .take(5)
        .find_map(|line| line.trim().strip_prefix("\"lockfileVersion\":"))
        .and_then(|rest| rest.trim().trim_end_matches(',').parse().ok())
}

/// The toolchain preflight every leg runs first: bun present, pinned
/// version honored, text lockfile available. `None` = this leg is skipped
/// (already reported with a println) — but under the REQUIRED gate every
/// one of those is a hard failure instead, because a CI leg that silently
/// skips is exactly the vacuous pass this suite had for months.
fn bun_toolchain(tag: &str) -> Option<(String, BunVersion)> {
    let Some(raw) = bun_version_output() else {
        assert!(
            !bun_required(),
            "SOCKET_PATCH_BUN_E2E_REQUIRED is set but `bun --version` did not run — \
             the matrix leg must install bun before running this suite"
        );
        println!("SKIP e2e_redirect_bun_build ({tag}): `bun` not installed");
        return None;
    };
    if let Some(pin) = pinned_bun_version() {
        assert_eq!(
            raw, pin,
            "SOCKET_PATCH_BUN_E2E_VERSION pins bun {pin} but PATH resolves bun {raw}: the \
             matrix must run the pinned version"
        );
    }
    let Some(version) = parse_bun_version(&raw) else {
        assert!(
            !bun_required(),
            "required bun toolchain reports an unparsable version {raw:?}"
        );
        println!("SKIP e2e_redirect_bun_build ({tag}): unparsable `bun --version` output {raw:?}");
        return None;
    };
    if version < TEXT_LOCK_FROM {
        assert!(
            !bun_required(),
            "bun {raw} has no text lockfile (the `--save-text-lockfile` opt-in exists from \
             1.1.39); a REQUIRED leg must not be scheduled on it"
        );
        println!(
            "SKIP e2e_redirect_bun_build ({tag}): bun {raw} predates the text bun.lock (1.1.39)"
        );
        return None;
    }
    Some((raw, version))
}

fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") && k.to_string_lossy() != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("BUN_INSTALL_CACHE_DIR");
}

fn bun(cwd: &Path, args: &[&str], cache_dir: &Path) -> Output {
    let mut cmd = Command::new("bun");
    cmd.args(args).current_dir(cwd);
    scrub_socket_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    cmd.env("BUN_INSTALL_CACHE_DIR", cache_dir);
    cmd.output().expect("failed to run bun")
}

/// The real binary with `--no-telemetry` appended: nothing in this suite
/// should ever post a telemetry event, mocked API or not.
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).arg("--no-telemetry").current_dir(cwd);
    scrub_socket_env(&mut cmd);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn sha512_sri_b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
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

/// A VALID npm tarball built from the ACTUALLY-installed package with the
/// entry point swapped for `replaced_index`. Built with the tar crate
/// rather than a system `tar` so the suite has no external-binary
/// dependency (bun installs from tar-crate output fine, as pnpm does in
/// `e2e_redirect_pnpm_build.rs`).
fn make_tgz_from_installed(pkg_dir: &Path, replaced_index: &[u8]) -> Vec<u8> {
    let pkg_dir = pkg_dir
        .canonicalize()
        .expect("installed package dir must resolve");
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![pkg_dir.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                files.push(p);
            }
        }
    }
    files.sort();
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for p in &files {
        let rel = p.strip_prefix(&pkg_dir).unwrap();
        // Tar entry names always use `/` regardless of host separator.
        let name = format!(
            "package/{}",
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        );
        let bytes = if rel == Path::new("index.js") {
            replaced_index.to_vec()
        } else {
            std::fs::read(p).unwrap()
        };
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, &name, bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

struct BunRedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    /// The pristine installed `index.js`.
    orig: Vec<u8>,
    /// `MARKER` + orig — what the honest hosted tarball carries.
    patched: Vec<u8>,
    /// `TAMPER_MARKER` + orig — what the tampered twin's route serves.
    tampered: Vec<u8>,
    /// bun.lock as it stood right before the hosted rewrite (after any
    /// relabel) — the byte-exact rollback target.
    lock_before: Vec<u8>,
    /// The `"lockfileVersion"` the rewrite must preserve.
    lock_version: u64,
    /// `bun --version`, verbatim, for messages.
    bun_raw: String,
    bun_version: BunVersion,
    _server: MockServer,
}

/// Which socket-patch invocation drives the hosted rewrite (step 3). Both
/// route through the same hosted engine (`get --mode hosted` hands its
/// selected (purl, uuid) pair to scan's `run_redirect_selected`), so every
/// lockfile/ledger assertion below is shared; only the argv and the outer
/// envelope shape differ.
#[derive(Clone, Copy, PartialEq)]
enum HostedDriver {
    /// `scan --mode hosted --vex …` — the original capstone path, in-run
    /// VEX assertions included.
    ScanVex,
    /// `get <uuid> --mode hosted` — the v3.6 per-advisory selector. The
    /// UUID identifier path is exempt from installed narrowing, so the
    /// fixture's view + reference mocks are all it needs. No manifest, no
    /// blobs, no vex flags (get has none).
    GetUuid,
}

/// Which lock the hosted rewrite runs on.
#[derive(Clone, Copy, PartialEq)]
enum LockShape {
    /// Whatever the installed bun wrote (asserted against the era table).
    Native,
    /// On bun ≥ 1.4 only: the native lockfileVersion-2 lock relabelled to 1
    /// (`configVersion` kept — the lock a 1.3.x bun wrote; dropping it
    /// would make bun add `"configVersion": 0` on the first plain install,
    /// bun's own migration and not ours). Below 1.4 the leg is PARTIAL:
    /// one binary cannot be both the writer and the newer reader.
    V1OnNewerBun,
}

/// Steps 1–3: real install, patched tarball + API mocks, the `driver`'s
/// hosted invocation, and the envelope/lockfile/ledger assertions.
/// `tamper_served_tarball` serves DIFFERENT bytes than the sha512 pinned
/// into the lock. `None` = skip (already reported).
async fn bun_hosted_project(
    tag: &str,
    tamper_served_tarball: bool,
    driver: HostedDriver,
    shape: LockShape,
) -> Option<BunRedirectFixture> {
    let (bun_raw, bun_version) = bun_toolchain(tag)?;
    if shape == LockShape::V1OnNewerBun && bun_version < LOCK_V2_FROM {
        println!(
            "PARTIAL e2e_redirect_bun_build ({tag}): bun {bun_raw} writes lockfileVersion {} \
             itself, so the newer-bun-on-a-v1-lock scenario needs bun >= 1.4 — leg not \
             applicable on this toolchain",
            expected_lock_version(bun_version)
        );
        return None;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"redirect-bun-capstone","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();

    // 1. REAL fixture: bun install (network here, private cache). Text lockfile.
    let cache = tmp.path().join("bun-cache");
    let install = bun(&proj, &fixture_install_args(bun_version), &cache);
    if !install.status.success() {
        assert!(
            !bun_required(),
            "required bun {bun_raw} fixture `bun install` failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&install.stdout),
            String::from_utf8_lossy(&install.stderr)
        );
        println!(
            "SKIP e2e_redirect_bun_build ({tag}): fixture `bun install` failed (registry \
             unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return None;
    }
    let lock_path = proj.join("bun.lock");
    if !lock_path.is_file() {
        assert!(
            !bun_required(),
            "required bun {bun_raw} produced no text bun.lock after {:?}",
            fixture_install_args(bun_version)
        );
        println!(
            "SKIP e2e_redirect_bun_build ({tag}): bun produced no text bun.lock (binary \
             lockfile?)"
        );
        return None;
    }
    // Hermeticity guard: the install must have gone through the PRIVATE
    // cache, or the fresh-checkout "empty cache" premise below is void.
    assert!(
        cache.is_dir() && std::fs::read_dir(&cache).unwrap().next().is_some(),
        "fixture install did not populate the private BUN_INSTALL_CACHE_DIR at {}",
        cache.display()
    );
    let native_lock = std::fs::read_to_string(&lock_path).unwrap();
    // The era table, asserted rather than assumed: 1.1.39–1.1.x opt-in
    // text lock → 0, 1.2–1.3 → 1, ≥ 1.4 → 2. Pinning the mapping is what
    // makes a lock-era CI leg prove the era it claims to cover.
    let native_version = lock_version(&native_lock).unwrap_or_else(|| {
        panic!("fixture bun.lock has no integer lockfileVersion in its head:\n{native_lock}")
    });
    assert_eq!(
        native_version,
        expected_lock_version(bun_version),
        "bun {bun_raw} wrote lockfileVersion {native_version}; the era table expects {} \
         (1.1.39–1.1.x → 0, 1.2–1.3 → 1, ≥ 1.4 → 2):\n{native_lock}",
        expected_lock_version(bun_version)
    );
    assert!(
        native_lock.contains(&format!("\"{DEP}@{DEP_VERSION}\", \"\"")),
        "pre-redirect packages entry must be the registry 4-tuple:\n{native_lock}"
    );
    let lock_version = match shape {
        LockShape::Native => native_version,
        LockShape::V1OnNewerBun => {
            // Splice ONLY the version line (v1 and v2 share one emitted
            // grammar; `configVersion` stays, see `LockShape`).
            let relabelled: String = native_lock
                .split_inclusive('\n')
                .map(|line| {
                    if line.trim_start().starts_with("\"lockfileVersion\":") {
                        "  \"lockfileVersion\": 1,\n".to_string()
                    } else {
                        line.to_string()
                    }
                })
                .collect();
            assert_eq!(
                lock_version(&relabelled),
                Some(1),
                "the relabelled fixture lock must read back as lockfileVersion 1:\n{relabelled}"
            );
            std::fs::write(&lock_path, relabelled).unwrap();
            1
        }
    };
    let lock_before = std::fs::read(&lock_path).unwrap();

    let installed_dir = proj.join("node_modules").join(DEP);
    let orig = std::fs::read(installed_dir.join("index.js")).expect("installed index.js");
    assert!(
        !orig.starts_with(MARKER.as_bytes()),
        "pristine install must not carry the marker"
    );
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let tampered: Vec<u8> = [TAMPER_MARKER.as_bytes(), orig.as_slice()].concat();

    // 2. Patched tarball from the installed package; its sha512 is the pin.
    //    The negative twin only tampers what the route SERVES (a different,
    //    still-valid tarball), so the pin is what catches the swap.
    let tgz = make_tgz_from_installed(&installed_dir, &patched);
    let sri = format!("sha512-{}", sha512_sri_b64(&tgz));
    let served: Vec<u8> = if tamper_served_tarball {
        let tampered_tgz = make_tgz_from_installed(&installed_dir, &tampered);
        assert_ne!(tampered_tgz, tgz, "the tampered tarball must differ");
        tampered_tgz
    } else {
        tgz.clone()
    };

    // 3. API mocks + the hosted tarball route bun will hit at install time.
    let server = MockServer::start().await;
    let hosted_url = format!(
        "{}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz",
        server.uri()
    );
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "redirect bun capstone fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": hosted_url,
                    "purl": PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": hosted_url,
                        "integrity": { "sha512": sri }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": compute_git_sha256_from_bytes(&orig),
                    "afterHash": compute_git_sha256_from_bytes(&patched),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-1111"], "summary": "redirect bun capstone vuln",
                    "severity": "high", "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_raw(served, "application/octet-stream"))
        .mount(&server)
        .await;

    // Step 3, per driver: scan --mode hosted --vex | get <uuid> --mode hosted.
    let server_uri = server.uri();
    let argv: Vec<&str> = match driver {
        HostedDriver::ScanVex => vec![
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
        HostedDriver::GetUuid => vec![
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
    let (code, stdout, stderr) = run_socket(&proj, &argv);
    assert_eq!(
        code, 0,
        "{} --mode hosted failed.\nstdout:\n{stdout}\nstderr:\n{stderr}",
        argv[0]
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "{} --mode hosted --json output is not JSON: {e}\nstdout:\n{stdout}",
            argv[0]
        )
    });
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "one dep redirected: {env}"
    );
    match driver {
        HostedDriver::ScanVex => {
            // In-run VEX (step 3 of the module doc): the envelope's vex block
            // plus the document's unverified `(redirected)` attestation.
            // Without these, a scan that silently skips the VEX write (or
            // emits the wrong statement) stays green — the exit code only
            // catches a HARD vex failure.
            assert_eq!(env["vex"]["path"], "out.vex.json", "vex block: {env}");
            assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
            assert_eq!(env["vex"]["format"], "openvex-0.2.0", "vex block: {env}");
            assert_eq!(
                env["vex"]["verified"], false,
                "in-run redirect VEX is attested from the ledger, not hash-verified: {env}"
            );
            let vex_doc: serde_json::Value =
                serde_json::from_slice(&std::fs::read(proj.join("out.vex.json")).unwrap()).unwrap();
            let stmts = vex_doc["statements"].as_array().unwrap();
            assert_eq!(
                stmts.len(),
                1,
                "exactly the redirected patch attested: {vex_doc}"
            );
            assert_eq!(
                stmts[0]["vulnerability"]["name"], GHSA,
                "vex doc: {vex_doc}"
            );
            assert_eq!(stmts[0]["status"], "not_affected", "vex doc: {vex_doc}");
            assert_eq!(
                stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL,
                "vex doc: {vex_doc}"
            );
            assert_eq!(
                stmts[0]["impact_statement"].as_str().unwrap(),
                format!("Patched via Socket patch {UUID} (redirected)"),
                "the in-run attestation must carry the (redirected) marker: {vex_doc}"
            );
        }
        HostedDriver::GetUuid => {
            // get's envelope nests the same redirect block into its own base
            // shape; nothing is downloaded into `.socket/` (the ledger IS the
            // persistence — parity with `scan --mode hosted`).
            assert_eq!(env["redirect"]["mode"], "hosted", "envelope: {env}");
            assert_eq!(env["found"], 1, "get keeps its found count: {env}");
            assert!(
                env.get("downloaded").is_none() && env.get("applied").is_none(),
                "hosted get downloads/applies nothing — those keys must be absent: {env}"
            );
            assert!(
                !proj.join(".socket").join("manifest.json").exists(),
                "get --mode hosted must NOT write the manifest"
            );
            assert!(
                !proj.join(".socket").join("blobs").exists(),
                "get --mode hosted must NOT persist blobs"
            );
            // Anti-vacuity oracle: the grant really came from the reference
            // endpoint (exactly one resolve for the one selected uuid).
            let reference_hits = server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|r| r.url.path().ends_with("/patches/package"))
                .count();
            assert_eq!(
                reference_hits, 1,
                "get --mode hosted must resolve exactly one reference grant"
            );
        }
    }

    // Lockfile pin: the hosted URL (as the tuple spec) + the patched sha512,
    // the registry 4-tuple gone, and the lock's own version line kept.
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.contains(&format!("\"{DEP}@{hosted_url}\"")),
        "bun.lock tuple spec must be name@<hosted url>; got:\n{lock}"
    );
    assert!(
        lock.contains(&sri),
        "bun.lock integrity must be the patched sha512 ({sri}); got:\n{lock}"
    );
    assert!(
        !lock.contains(&format!("\"{DEP}@{DEP_VERSION}\", \"\"")),
        "the registry 4-tuple must be gone after the rewrite:\n{lock}"
    );
    assert_eq!(
        self::lock_version(&lock),
        Some(lock_version),
        "the rewrite must preserve the lockfileVersion line verbatim; got:\n{lock}"
    );

    let ledger = std::fs::read_to_string(redirect_ledger(&proj)).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA),
        "redirect ledger must embed the patch record + vulnerability: {ledger}"
    );

    Some(BunRedirectFixture {
        tmp,
        proj,
        orig,
        patched,
        tampered,
        lock_before,
        lock_version,
        bun_raw,
        bun_version,
        _server: server,
    })
}

fn redirect_ledger(proj: &Path) -> PathBuf {
    proj.join(".socket")
        .join("vendor")
        .join("redirect-state.json")
}

/// Fresh dir `<tmp>/<name>` with only the committable files (package.json,
/// bun.lock, and `.socket/` when it exists — rollback removes it).
fn fresh_checkout(fx: &BunRedirectFixture, name: &str) -> PathBuf {
    let fresh = fx.tmp.path().join(name);
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(fx.proj.join("bun.lock"), fresh.join("bun.lock")).unwrap();
    if fx.proj.join(".socket").is_dir() {
        copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    }
    fresh
}

/// `bun install --frozen-lockfile` in a fresh checkout named `name` against
/// an empty cache.
fn fresh_frozen_install(fx: &BunRedirectFixture, name: &str) -> (PathBuf, Output) {
    let fresh = fresh_checkout(fx, name);
    let fresh_cache = fx.tmp.path().join(format!("{name}-bun-cache"));
    let ci = bun(
        &fresh,
        &["install", "--frozen-lockfile", "--ignore-scripts"],
        &fresh_cache,
    );
    (fresh, ci)
}

/// Shared fresh-checkout proof: `bun install --frozen-lockfile` against an
/// empty cache must materialize the PATCHED bytes from the hosted tarball;
/// then an ORDINARY `bun install` (node_modules removed, another empty
/// cache) must leave bun.lock byte-identical and land the marker again.
/// Frozen mode never writes the lock, so only the plain install can catch
/// bun re-serializing the URL tuple (backtest twin: `ordinaryStableLock`).
fn assert_patched_fresh_install(fx: &BunRedirectFixture) {
    let (fresh, ci) = fresh_frozen_install(fx, "fresh");
    assert!(
        ci.status.success(),
        "fresh-checkout `bun install --frozen-lockfile` must succeed from the hosted patch \
         tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed_index = fresh.join("node_modules").join(DEP).join("index.js");
    let installed = std::fs::read(&installed_index).unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "bun must install the PATCHED bytes from the hosted patch; got:\n{}",
        String::from_utf8_lossy(&installed[..installed.len().min(120)])
    );
    assert_eq!(
        installed, fx.patched,
        "fresh install must be byte-identical to the patched content"
    );
    eprintln!(
        "FRESH INSTALL OK (bun {}, lockfileVersion {})",
        fx.bun_raw, fx.lock_version
    );

    // Ordinary install: the lock must survive bun's own re-serialization.
    let wired_lock = std::fs::read(fx.proj.join("bun.lock")).unwrap();
    std::fs::remove_dir_all(fresh.join("node_modules")).unwrap();
    let plain_cache = fx.tmp.path().join("fresh-plain-bun-cache");
    let plain = bun(&fresh, &["install", "--ignore-scripts"], &plain_cache);
    assert!(
        plain.status.success(),
        "plain `bun install` on the redirected lock must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&plain.stdout),
        String::from_utf8_lossy(&plain.stderr),
    );
    assert_eq!(
        std::fs::read(fresh.join("bun.lock")).unwrap(),
        wired_lock,
        "an ORDINARY `bun install` must leave the redirected bun.lock byte-identical \
         (re-serialization drift would churn every commit)"
    );
    assert_eq!(
        std::fs::read(&installed_index).unwrap(),
        fx.patched,
        "the ordinary install must land the patched bytes too"
    );
    eprintln!("PLAIN INSTALL LOCK-STABLE");
}

// ── the capstone ──────────────────────────────────────────────────────

// #[serial]: bun shares an on-disk cache/registry-metadata directory across
// installs of the same URL; serializing keeps the tampered twin from reusing
// the main leg's honest bytes (each leg also uses its own cache dir).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_redirect_fresh_checkout_installs_patched_bytes() {
    let Some(fx) =
        bun_hosted_project("main", false, HostedDriver::ScanVex, LockShape::Native).await
    else {
        return;
    };
    assert_patched_fresh_install(&fx);
}

/// get-driven twin (v3.6): `get <uuid> --mode hosted` must land the SAME
/// hosted rewrite as the scan capstone — same engine by construction — and a
/// fresh checkout carrying only package.json + bun.lock + .socket/ must
/// install the patched bytes from the hosted tarball. The fixture's GetUuid
/// arm already proved the no-manifest/no-blobs posture and the ledger write.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_get_uuid_hosted_fresh_checkout_installs() {
    let Some(fx) =
        bun_hosted_project("get-uuid", false, HostedDriver::GetUuid, LockShape::Native).await
    else {
        return;
    };
    assert_patched_fresh_install(&fx);
}

/// Cross-version leg: a team on bun ≥ 1.4 keeps installing from the
/// lockfileVersion-1 lock their 1.3.x wrote — bun 1.4 reads it and never
/// bumps it in place — so the hosted rewrite must land on that lock, keep
/// `"lockfileVersion": 1`, frozen-install the patched bytes, and survive an
/// ordinary install byte-for-byte (no bump to 2). PARTIAL below bun 1.4:
/// one binary cannot be both the older writer and the newer reader.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_redirect_lock_v1_on_newer_bun_fresh_checkout_installs_patched_bytes() {
    let Some(fx) = bun_hosted_project(
        "lock-v1-on-newer-bun",
        false,
        HostedDriver::ScanVex,
        LockShape::V1OnNewerBun,
    )
    .await
    else {
        return;
    };
    assert!(
        fx.bun_version >= LOCK_V2_FROM && fx.lock_version == 1,
        "leg precondition: bun {} (>= 1.4) on a relabelled lockfileVersion-1 lock",
        fx.bun_raw
    );
    assert_patched_fresh_install(&fx);
    // The plain install above left the lock byte-identical; say the version
    // part out loud so a future "bun 1.x bumps v1 in place" shows up by name.
    let lock = std::fs::read_to_string(fx.proj.join("bun.lock")).unwrap();
    assert_eq!(
        lock_version(&lock),
        Some(1),
        "bun {} must not bump the committed lockfileVersion-1 lock:\n{lock}",
        fx.bun_raw
    );
}

/// Negative twin: the hosted route serves TAMPERED bytes (a different valid
/// tarball) while the lock pins the real sha512. From bun 1.3.10 the fresh
/// frozen install must refuse on the integrity check; earlier bun installs
/// the tampered bytes with exit 0 and the leg pins THAT (PARTIAL), so the
/// digest boundary is asserted from both sides across the lock-era legs.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_redirect_tampered_hosted_tarball_digest_boundary() {
    let Some(fx) =
        bun_hosted_project("tampered", true, HostedDriver::ScanVex, LockShape::Native).await
    else {
        return;
    };

    let (fresh, ci) = fresh_frozen_install(&fx, "fresh-tampered");
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr)
    );
    if fx.bun_version >= TARBALL_INTEGRITY_ENFORCED_FROM {
        assert!(
            !ci.status.success(),
            "bun {} install MUST fail when the served tarball does not match the pinned \
             sha512 (URL-tarball digests are enforced from 1.3.10).\n{chatter}",
            fx.bun_raw
        );
        let lower = chatter.to_lowercase();
        assert!(
            lower.contains("integrity")
                || lower.contains("checksum")
                || lower.contains("hash")
                || chatter.contains("IntegrityCheckFailed"),
            "the failure must be the integrity check, not something incidental:\n{chatter}"
        );
        eprintln!("TAMPER REJECTED OK (bun {})", fx.bun_raw);
    } else {
        assert!(
            ci.status.success(),
            "bun {} (< 1.3.10) does not verify URL-tarball digests, so the tampered install \
             must still exit 0 — a failure here means the boundary moved.\n{chatter}",
            fx.bun_raw
        );
        let installed =
            std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
        assert_eq!(
            installed, fx.tampered,
            "bun {} installed neither the tampered bytes nor failed: the boundary model is wrong",
            fx.bun_raw
        );
        println!(
            "PARTIAL e2e_redirect_bun_build (tampered): bun {} does not verify URL tarball \
             digests (enforced from 1.3.10) — rejection proof unavailable, acceptance pinned",
            fx.bun_raw
        );
    }
}

/// Rollback leg: after the hosted rewrite and the fresh-checkout proof,
/// `rollback --yes` (unscoped — the whole-ledger reverse replay) must
/// restore bun.lock byte-for-byte to the pre-redirect snapshot and delete
/// the redirect ledger, and a fresh frozen install of the restored lock
/// must land the ORIGINAL registry bytes — the marker gone.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_redirect_rollback_restores_lock_and_original_install() {
    let Some(fx) =
        bun_hosted_project("rollback", false, HostedDriver::ScanVex, LockShape::Native).await
    else {
        return;
    };
    assert_patched_fresh_install(&fx);

    let proj = &fx.proj;
    let (code, stdout, stderr) = run_socket(
        proj,
        &[
            "rollback",
            "--yes",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "rollback failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("rollback --json output is not JSON: {e}\nstdout:\n{stdout}"));
    assert_eq!(env["status"], "success", "rollback envelope: {env}");
    assert_eq!(
        std::fs::read(proj.join("bun.lock")).unwrap(),
        fx.lock_before,
        "rollback must restore bun.lock byte-identical to the pre-redirect snapshot"
    );
    assert!(
        !redirect_ledger(proj).exists(),
        "rollback must delete the redirect ledger"
    );
    let restored = std::fs::read_to_string(proj.join("bun.lock")).unwrap();
    assert!(
        restored.contains(&format!("\"{DEP}@{DEP_VERSION}\", \"\"")),
        "the registry 4-tuple must be back after rollback:\n{restored}"
    );
    eprintln!("ROLLBACK OK");

    // The restored lock installs the ORIGINAL bytes from the registry.
    let (fresh, ci) = fresh_frozen_install(&fx, "fresh-rolled-back");
    assert!(
        ci.status.success(),
        "fresh-checkout `bun install --frozen-lockfile` of the restored lock must \
         succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        !installed.starts_with(MARKER.as_bytes()),
        "after rollback bun must install the ORIGINAL bytes, not the patch"
    );
    assert_eq!(
        installed, fx.orig,
        "after rollback the fresh install must be byte-identical to the pristine package"
    );
}
