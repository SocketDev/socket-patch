//! Real-bun capstone e2e for `socket-patch vendor` — the committability
//! proof for the bun (text `bun.lock`) flavor.
//!
//! Drives the REAL `bun` (network used for fixture setup only):
//!   1. `bun install` of left-pad@1.3.0 into a tempdir (private
//!      `BUN_INSTALL_CACHE_DIR`). The text `bun.lock` is the default from
//!      bun 1.2.0 (lockfileVersion 1; 2 from 1.4.0); on 1.1.39–1.1.x it is
//!      the `--save-text-lockfile` opt-in (lockfileVersion 0), which the
//!      fixture passes for those releases, and the fixture ASSERTS the
//!      version it got matches that era table. Bun before 1.1.39 has no
//!      text lockfile at all and the suite skips (or, under the REQUIRED
//!      gate, fails — such a leg must not be scheduled).
//!   2. Hand-stage a `.socket/` manifest + blob from the ACTUAL installed
//!      bytes (a marker comment prepended to `index.js`).
//!   3. `socket-patch vendor --json --offline` — assert the deterministic
//!      tarball lands at `.socket/vendor/npm/<uuid>/…` and the bun.lock
//!      `packages` entry is rewritten from the registry 4-tuple to the
//!      local-tarball 3-tuple `["<name>@<rel-path>", {deps}, "sha512-<ours>"]`
//!      (spike BN1/BN3). package.json is left UNTOUCHED. The registry
//!      4-tuple spelling is identical across lockfileVersion 0, 1 and 2, so
//!      every assertion after the fixture guard is version-independent.
//!   4. **Fresh-checkout proof**: copy ONLY the committable files
//!      (package.json + bun.lock + .socket/) to a new dir, an EMPTY
//!      `BUN_INSTALL_CACHE_DIR`, and run the spike's strictest invocation
//!      `bun install --frozen-lockfile` — the patched bytes MUST be what bun
//!      installs (BN7). Then the ORDINARY install: `node_modules` removed,
//!      another empty cache, plain `bun install` — bun.lock must stay
//!      byte-identical (frozen mode never writes the lock, so only a plain
//!      install can observe re-serialization drift; the backtest's
//!      `ordinaryStableLock` is the matrix twin) and the marker bytes must
//!      land again.
//!   5. **Repair proof**: delete `.socket/vendor/npm/<uuid>/` outright,
//!      `repair --offline` must rebuild the tarball byte-identically from
//!      the installed copy + blob without touching bun.lock, and a fresh
//!      cold-cache frozen install must again land the marker bytes.
//!   6. Idempotency: re-running vendor leaves bun.lock byte-identical.
//!   7. **Revert proof**: `vendor --revert` restores bun.lock byte-for-byte
//!      and removes `.socket/vendor/` entirely.
//!
//! The get-driven twin (v3.6) replaces steps 2–3 with a wiremock
//! `view/{uuid}` (same hashes, base64 `blobContent` of the after bytes) and
//! `get <uuid> --mode vendored --vendor-source build` — scan's vendored
//! posture end to end: manifest + committed artifact + ledger + wired lock,
//! NO `.socket/blobs` — then re-runs the same fresh-checkout install proof.
//! The revert half is not repeated there: `vendor --revert` on the
//! capstone already covers it (same ledger, same engine).
//!
//! The scoped leg vendors a DIFFERENT target: `@scope/pkg@1.0.0`, a scoped
//! package with `dependencies` and a `bin`, served by a wiremock npm
//! registry through bun's `[install.scopes]` (a private scoped registry —
//! the common real-world shape). Bun records it as
//! `["@scope/pkg@1.0.0", "<tarball url>", { "dependencies": {…}, "bin": {…}
//! }, "sha512-…"]`; the rewrite must carry that meta object VERBATIM into
//! the local-tarball 3-tuple (whose path keeps the scope dir:
//! `.socket/vendor/npm/<uuid>/@scope/pkg-1.0.0.tgz`), and the fresh install
//! must prove bun honored it: the dependency installs and the bin is
//! linked. A meta-dropping regression is silent under every left-pad leg
//! (bun installs a `{}`-meta tuple with exit 0, patched bytes and a stable
//! lock — and no deps, no bin).
//!
//! The tampered twin swaps the committed tarball for a DIFFERENT valid
//! tarball while bun.lock keeps our sha512: bun verifies the digest of
//! local-tarball tuples only from 1.3.10 (`Integrity check failed`), so the
//! fresh frozen install MUST fail there and MUST succeed — installing the
//! tampered bytes — on every older text-lock bun (reported as PARTIAL). The
//! boundary is pinned as [`TARBALL_INTEGRITY_ENFORCED_FROM`]; the hosted
//! twin lives in `e2e_redirect_bun_build.rs`.
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

use sha2::{Digest, Sha256, Sha512};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;

const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
/// Content of the tampered twin's replacement tarball — distinct from the
/// pristine AND the patched bytes so "bun installed the tampered bytes" is
/// a real assertion, not a trailing-byte no-op.
const TAMPER_MARKER: &str = "/* SOCKET-TAMPERED */\n";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const ORG: &str = "test-org";

/// The scoped, dependency-bearing target of the meta-preserving leg. It
/// exists only in the wiremock registry this suite runs; bun fetches it
/// through `[install.scopes]` and left-pad (its one dependency) from the
/// real registry like every other fixture.
const SCOPED_NAME: &str = "@scope/pkg";
const SCOPED_VERSION: &str = "1.0.0";
const SCOPED_BIN: &str = "scope-pkg";
const SCOPED_INDEX: &[u8] = b"module.exports = require('left-pad');\n";
/// The meta object bun writes for it, byte-exact (bun serializes
/// `dependencies` before `bin`; identical on lockfileVersion 0, 1 and 2).
/// The rewrite must carry this into the 3-tuple verbatim.
const SCOPED_META: &str =
    r#"{ "dependencies": { "left-pad": "1.3.0" }, "bin": { "scope-pkg": "bin/cli.js" } }"#;

/// `(major, minor, patch)` of the bun on PATH.
type BunVersion = (u64, u64, u64);

/// First bun that verifies the sha512 of URL / local-tarball tuples on
/// install (1.3.9 installs a mismatched tarball with exit 0; 1.3.10 fails
/// with `Integrity check failed`). NOT 1.3.14 — that figure came from a
/// matrix that sampled only 1.3.0 and 1.3.14. Registry 4-tuples are
/// verified from 1.2.0 and are not what the vendored rewrite produces.
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
    cache_env::scrub_ambient_bun_env(&mut probe);
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
        println!("SKIP e2e_vendor_bun_build ({tag}): `bun` not installed");
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
        println!("SKIP e2e_vendor_bun_build ({tag}): unparsable `bun --version` output {raw:?}");
        return None;
    };
    if version < TEXT_LOCK_FROM {
        assert!(
            !bun_required(),
            "bun {raw} has no text lockfile (the `--save-text-lockfile` opt-in exists from \
             1.1.39); a REQUIRED leg must not be scheduled on it"
        );
        println!(
            "SKIP e2e_vendor_bun_build ({tag}): bun {raw} predates the text bun.lock (1.1.39)"
        );
        return None;
    }
    Some((raw, version))
}

/// Run `bun <args>` in `cwd` with the given private cache dir, the shared
/// cache sandbox for everything bun keeps outside that dir (`~/.bun`, the
/// npmrc it reads), and the ambient env scrubbed by the scrub the three bun
/// suites share (`cache_env::scrub_ambient_bun_env`: `SOCKET_*`, every
/// `BUN_*`, case-insensitive `npm_config_*` — an ambient registry mirror
/// would put the mirror tarball URL in the 4-tuple's registry slot and fail
/// the pre-vendor assertions).
fn bun(cwd: &Path, args: &[&str], cache_dir: &Path) -> Output {
    let mut cmd = Command::new("bun");
    cmd.args(args).current_dir(cwd);
    // Scrub BEFORE seeding: the scrub removes BUN_INSTALL_CACHE_DIR, and
    // Command's last env call wins.
    cache_env::scrub_ambient_bun_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    cmd.env("BUN_INSTALL_CACHE_DIR", cache_dir);
    cmd.output().expect("failed to run bun")
}

/// The real binary with `--no-telemetry` appended: nothing in this suite
/// should ever post a telemetry event, mocked API or not.
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).arg("--no-telemetry").current_dir(cwd);
    cache_env::scrub_ambient_bun_env(&mut cmd);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
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

fn sri(bytes: &[u8]) -> String {
    format!("sha512-{}", b64(&Sha512::digest(bytes)))
}

fn parse_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("--json output is not JSON: {e}\nstdout:\n{stdout}"))
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

/// A gzipped npm tarball from `(entry name under package/, bytes, mode)`
/// triples, built with the tar crate so the suite has no system-`tar`
/// dependency (Windows runners included).
fn build_tgz(entries: &[(String, Vec<u8>, u32)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (name, bytes, mode) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(*mode);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("package/{name}"), bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// A VALID npm tarball built from the ACTUALLY-installed package with the
/// entry point swapped — the tampered twin's replacement artifact. The
/// point is a sha512 that differs from the one bun.lock pins while the
/// archive still extracts, so "bun installed the tampered bytes" can be
/// asserted on the pre-1.3.10 releases that never check the digest.
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
    let entries: Vec<(String, Vec<u8>, u32)> = files
        .iter()
        .map(|p| {
            let rel = p.strip_prefix(&pkg_dir).unwrap();
            // Tar entry names always use `/` regardless of host separator.
            let name = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let bytes = if rel == Path::new("index.js") {
                replaced_index.to_vec()
            } else {
                std::fs::read(p).unwrap()
            };
            (name.clone(), bytes, file_mode(p, &name))
        })
        .collect();
    build_tgz(&entries)
}

#[cfg(unix)]
fn file_mode(p: &Path, _name: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_mode(_p: &Path, name: &str) -> u32 {
    if name.starts_with("bin/") {
        0o755
    } else {
        0o644
    }
}

/// The scoped target's registry tarball: package.json with the dependency
/// and the bin, the entry point, and the (executable) bin script.
fn scoped_registry_tgz() -> Vec<u8> {
    let pkg_json = serde_json::json!({
        "name": SCOPED_NAME,
        "version": SCOPED_VERSION,
        "main": "index.js",
        "dependencies": { DEP: DEP_VERSION },
        "bin": { SCOPED_BIN: "bin/cli.js" },
    });
    build_tgz(&[
        (
            "package.json".into(),
            serde_json::to_vec_pretty(&pkg_json).unwrap(),
            0o644,
        ),
        ("index.js".into(), SCOPED_INDEX.to_vec(), 0o644),
        (
            "bin/cli.js".into(),
            b"#!/usr/bin/env node\nconsole.log('scope-pkg cli');\n".to_vec(),
            0o755,
        ),
    ])
}

/// A wiremock npm registry for the scoped target: the packument (bun asks
/// for `/@scope%2fpkg`) and the tarball it points at. Integrity only — bun
/// verifies the sha512 and needs no `shasum`.
async fn mount_scoped_registry(server: &MockServer, tgz: Vec<u8>) {
    let tarball_url = format!("{}/@scope/pkg/-/pkg-{SCOPED_VERSION}.tgz", server.uri());
    Mock::given(method("GET"))
        .and(path_regex(r"^/@scope(%2[fF]|/)pkg$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": SCOPED_NAME,
            "dist-tags": { "latest": SCOPED_VERSION },
            "versions": {
                SCOPED_VERSION: {
                    "name": SCOPED_NAME,
                    "version": SCOPED_VERSION,
                    "dependencies": { DEP: DEP_VERSION },
                    "bin": { SCOPED_BIN: "bin/cli.js" },
                    "dist": { "tarball": tarball_url, "integrity": sri(&tgz) }
                }
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/@scope/pkg/-/pkg-{SCOPED_VERSION}.tgz")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(tgz, "application/octet-stream"))
        .mount(server)
        .await;
}

/// Which package the vendored rewrite targets.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Target {
    /// left-pad@1.3.0 from the real registry: unscoped, `{}` meta — the
    /// original capstone target.
    LeftPad,
    /// `@scope/pkg@1.0.0` from the suite's wiremock registry via
    /// `[install.scopes]`: scoped key, non-empty `{dependencies, bin}` meta.
    ScopedWithDeps,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Target::LeftPad => DEP,
            Target::ScopedWithDeps => SCOPED_NAME,
        }
    }
    fn version(self) -> &'static str {
        match self {
            Target::LeftPad => DEP_VERSION,
            Target::ScopedWithDeps => SCOPED_VERSION,
        }
    }
    /// The PURL the CLI derives for it (`@` is percent-encoded in npm PURLs).
    fn purl(self) -> &'static str {
        match self {
            Target::LeftPad => "pkg:npm/left-pad@1.3.0",
            Target::ScopedWithDeps => "pkg:npm/%40scope/pkg@1.0.0",
        }
    }
    /// The meta object bun writes for it, byte-exact.
    fn meta(self) -> &'static str {
        match self {
            Target::LeftPad => "{}",
            Target::ScopedWithDeps => SCOPED_META,
        }
    }
    fn installed_dir(self, root: &Path) -> PathBuf {
        let nm = root.join("node_modules");
        match self {
            Target::LeftPad => nm.join(DEP),
            Target::ScopedWithDeps => nm.join("@scope").join("pkg"),
        }
    }
    /// The vendored tarball's path under `.socket/vendor/npm/<uuid>/` — the
    /// scope dir is kept as a directory level.
    fn vendored_tgz_rel(self) -> String {
        match self {
            Target::LeftPad => format!("{DEP}-{DEP_VERSION}.tgz"),
            Target::ScopedWithDeps => format!("@scope/pkg-{SCOPED_VERSION}.tgz"),
        }
    }
    fn package_json(self) -> String {
        format!(
            r#"{{"name":"bun-capstone","version":"0.0.0","private":true,"dependencies":{{"{}":"{}"}}}}"#,
            self.name(),
            self.version()
        )
    }
}

/// The `packages` line for `name` in a bun.lock (`"name": [...]`).
fn packages_line(lock: &str, name: &str) -> String {
    let key = format!("\"{name}\": [");
    lock.lines()
        .find(|l| l.trim_start().starts_with(&key))
        .unwrap_or_else(|| panic!("no packages entry for {name} in:\n{lock}"))
        .to_string()
}

/// The `sha512-…` integrity token of a packages line (its last element).
fn line_sha512(line: &str) -> String {
    let start = line
        .rfind("\"sha512-")
        .unwrap_or_else(|| panic!("no sha512 in packages line: {line}"));
    let rest = &line[start + 1..];
    let end = rest.find('"').unwrap();
    rest[..end].to_string()
}

// ── shared fixture (steps 1–2) ────────────────────────────────────────

/// The real-bun project both capstones drive, plus the pre-vendor snapshots
/// the wiring/revert assertions diff against.
struct BunProject {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    target: Target,
    orig: Vec<u8>,
    patched: Vec<u8>,
    lock_before: Vec<u8>,
    pkg_before: Vec<u8>,
    /// bun's registry 4-tuple for the target, up to its integrity — the
    /// spelling that must be GONE after the rewrite.
    registry_tuple_head: String,
    /// The registry integrity bun recorded — must NOT survive the rewrite.
    registry_sha512: String,
    /// `bun --version`, verbatim, for messages.
    bun_raw: String,
    bun_version: BunVersion,
    /// The lockfileVersion this bun wrote — asserted against the era table.
    lock_version: u64,
}

/// Steps 1–2 of the module doc, shared by every leg: a tempdir project
/// depending on the target, a REAL `bun install` (network here, private
/// cache) with the hermeticity guard, pristine-byte checks, and the
/// patched-content twin of the installed `index.js`. `scoped_registry` is
/// the wiremock registry URI for [`Target::ScopedWithDeps`] (mounted by
/// the caller — the fixture writes the matching `bunfig.toml`). `None` =
/// soft-skip, already reported with a println (a hard failure instead
/// under the REQUIRED gate).
fn bun_project(tag: &str, target: Target, scoped_registry: Option<&str>) -> Option<BunProject> {
    let (bun_raw, bun_version) = bun_toolchain(tag)?;

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("package.json"), target.package_json()).unwrap();
    let mut registry_field = String::new();
    if target == Target::ScopedWithDeps {
        let registry = scoped_registry.expect("the scoped target needs its wiremock registry");
        // bun's scoped-registry config — a committable file, so it travels
        // with every fresh checkout below.
        std::fs::write(
            proj.join("bunfig.toml"),
            format!("[install.scopes]\n\"@scope\" = {{ url = \"{registry}/\" }}\n"),
        )
        .unwrap();
        // For a non-default registry bun records the TARBALL URL as the
        // 4-tuple's registry field.
        registry_field = format!("{registry}/@scope/pkg/-/pkg-{SCOPED_VERSION}.tgz");
    }

    // 1. REAL fixture: bun install (network allowed here, private cache).
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
            "SKIP e2e_vendor_bun_build ({tag}): fixture `bun install` failed (registry \
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
            "SKIP e2e_vendor_bun_build ({tag}): bun produced no text bun.lock (binary \
             lockfile?) — this bun version's default lockfile is not the wirable text form"
        );
        return None;
    }
    // Hermeticity guard: the install must have gone through the PRIVATE cache.
    // If BUN_INSTALL_CACHE_DIR never reached the child, bun silently used the
    // user's global cache and the fresh-checkout "empty cache" premise is void.
    assert!(
        cache.is_dir() && std::fs::read_dir(&cache).unwrap().next().is_some(),
        "fixture install did not populate the private BUN_INSTALL_CACHE_DIR at {}",
        cache.display()
    );

    let installed_index = target.installed_dir(&proj).join("index.js");
    let orig = std::fs::read(&installed_index).expect("installed index.js");
    assert!(
        !orig.starts_with(MARKER.as_bytes()),
        "pristine install must not carry the marker"
    );
    if target == Target::ScopedWithDeps {
        assert_eq!(
            orig, SCOPED_INDEX,
            "bun must have installed the mock registry's bytes"
        );
    }
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();

    let lock_before = std::fs::read(&lock_path).expect("bun.lock after bun install");
    let pkg_before = std::fs::read(proj.join("package.json")).expect("package.json");
    let lock_before_str = String::from_utf8(lock_before.clone()).unwrap();
    // The era table, asserted rather than assumed: 1.1.39–1.1.x opt-in
    // text lock → 0, 1.2–1.3 → 1, ≥ 1.4 → 2. All three are one emitted
    // grammar for registry entries and all three are wirable; pinning the
    // mapping is what makes a lock-era CI leg prove the era it claims.
    let lock_version = lock_version(&lock_before_str).unwrap_or_else(|| {
        panic!("fixture bun.lock has no integer lockfileVersion in its head:\n{lock_before_str}")
    });
    assert_eq!(
        lock_version,
        expected_lock_version(bun_version),
        "bun {bun_raw} wrote lockfileVersion {lock_version}; the era table expects {} \
         (1.1.39–1.1.x → 0, 1.2–1.3 → 1, ≥ 1.4 → 2):\n{lock_before_str}",
        expected_lock_version(bun_version)
    );
    // Pre-vendor: the registry 4-tuple, with bun's real registry field and
    // meta object for this target — one spelling across 0/1/2.
    let registry_tuple_head = format!(
        "\"{}@{}\", \"{registry_field}\", {}, \"sha512-",
        target.name(),
        target.version(),
        target.meta()
    );
    assert!(
        lock_before_str.contains(&registry_tuple_head),
        "pre-vendor packages entry must be the registry 4-tuple {registry_tuple_head}…:\n\
         {lock_before_str}"
    );
    let registry_sha512 = line_sha512(&packages_line(&lock_before_str, target.name()));

    Some(BunProject {
        tmp,
        proj,
        target,
        orig,
        patched,
        lock_before,
        pkg_before,
        registry_tuple_head,
        registry_sha512,
        bun_raw,
        bun_version,
        lock_version,
    })
}

fn vendored_dir(proj: &Path) -> PathBuf {
    proj.join(".socket").join("vendor").join("npm").join(UUID)
}

fn vendored_tgz(fx: &BunProject) -> PathBuf {
    vendored_dir(&fx.proj).join(fx.target.vendored_tgz_rel())
}

/// Hand-stage the `.socket/` manifest + blob for the fixture's target from
/// the installed bytes (the capstone's step 2).
fn stage_patch(fx: &BunProject) {
    let socket = fx.proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": { fx.target.purl(): {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": git_sha256(&fx.orig),
                "afterHash": git_sha256(&fx.patched),
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
    std::fs::write(
        socket.join("blobs").join(git_sha256(&fx.patched)),
        &fx.patched,
    )
    .unwrap();
}

/// `vendor --json --offline` over the fixture; the (code, stdout, stderr).
fn run_vendor(fx: &BunProject, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![
        "vendor",
        "--json",
        "--offline",
        "--cwd",
        fx.proj.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run_socket(&fx.proj, &args)
}

/// The on-disk vendored state BOTH drivers (`vendor --offline`, `get <uuid>
/// --mode vendored`) must produce: the committed artifact + informational
/// marker + ledger, the bun.lock `packages` entry rewritten from the
/// registry 4-tuple to the local-tarball 3-tuple with the meta object
/// carried VERBATIM and OUR recomputed integrity, and package.json
/// untouched.
fn assert_vendored_on_disk(fx: &BunProject) {
    let proj = &fx.proj;
    let tgz_rel = format!(".socket/vendor/npm/{UUID}/{}", fx.target.vendored_tgz_rel());
    assert!(
        vendored_tgz(fx).is_file(),
        "vendored tarball missing at {tgz_rel}"
    );
    assert!(
        vendored_dir(proj)
            .join("socket-patch.vendor.json")
            .is_file(),
        "informational vendor marker missing"
    );
    assert!(
        proj.join(".socket")
            .join("vendor")
            .join("state.json")
            .is_file(),
        "vendor ledger missing"
    );

    // bun.lock packages entry rewritten to the local-tarball 3-tuple:
    // element 0 = `<name>@<bare-rel-path>` (no `file:`/`./`), the meta
    // object shifts to index 1 unchanged, integrity is the recomputed
    // sha512 of OUR tarball.
    let lock_after = std::fs::read_to_string(proj.join("bun.lock")).unwrap();
    let local_tuple_head = format!(
        "\"{}@{tgz_rel}\", {}, \"sha512-",
        fx.target.name(),
        fx.target.meta()
    );
    assert!(
        lock_after.contains(&local_tuple_head),
        "bun.lock packages entry must be the local-tarball 3-tuple {local_tuple_head}…; got:\n\
         {lock_after}"
    );
    assert!(
        !lock_after.contains(&fx.registry_tuple_head),
        "the registry 4-tuple must be gone after the rewrite:\n{lock_after}"
    );
    assert!(
        !lock_after.contains(&fx.registry_sha512),
        "the inherited registry integrity must NOT survive the rewrite:\n{lock_after}"
    );
    // The rewrite must keep the lock's own version line — a v0 lock stays
    // v0, a v2 lock stays v2 (no silent format bump by the CLI).
    assert_eq!(
        lock_version(&lock_after),
        Some(fx.lock_version),
        "the vendored rewrite must preserve the lockfileVersion line verbatim:\n{lock_after}"
    );
    if fx.target == Target::ScopedWithDeps {
        // The dependency's own registry entry is not the target: untouched.
        let before = String::from_utf8(fx.lock_before.clone()).unwrap();
        assert_eq!(
            packages_line(&lock_after, DEP),
            packages_line(&before, DEP),
            "the un-patched dependency's registry 4-tuple must be byte-identical:\n{lock_after}"
        );
    }
    // package.json is left untouched by the lock-only bun wiring.
    assert_eq!(
        std::fs::read(proj.join("package.json")).unwrap(),
        fx.pkg_before,
        "bun vendoring is lock-only; package.json must stay byte-identical"
    );
}

/// Fresh dir `<tmp>/<name>` holding ONLY the committable files
/// (package.json, bun.lock, bunfig.toml when the project has one, and
/// .socket/).
fn fresh_checkout(fx: &BunProject, name: &str) -> PathBuf {
    let fresh = fx.tmp.path().join(name);
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(fx.proj.join("bun.lock"), fresh.join("bun.lock")).unwrap();
    if fx.proj.join("bunfig.toml").is_file() {
        std::fs::copy(fx.proj.join("bunfig.toml"), fresh.join("bunfig.toml")).unwrap();
    }
    copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    fresh
}

/// `bun install --frozen-lockfile` in a fresh checkout named `name` against
/// an EMPTY cache — the spike-proven strictest invocation.
fn fresh_frozen_install(fx: &BunProject, name: &str) -> (PathBuf, Output) {
    let fresh = fresh_checkout(fx, name);
    let fresh_cache = fx.tmp.path().join(format!("{name}-bun-cache"));
    let ci = bun(
        &fresh,
        &["install", "--frozen-lockfile", "--ignore-scripts"],
        &fresh_cache,
    );
    (fresh, ci)
}

/// For the scoped target: bun must have honored the meta object it read
/// from the local-tarball 3-tuple — the dependency is installed and the
/// bin linked (as `node_modules/.bin/scope-pkg`, or its `.exe`/`.cmd`
/// shims on Windows). Neither happens when the meta is `{}`.
fn assert_scoped_meta_honored(fresh: &Path) {
    assert!(
        fresh
            .join("node_modules")
            .join(DEP)
            .join("package.json")
            .is_file(),
        "bun must install the scoped package's `dependencies` from the 3-tuple meta"
    );
    let bin_dir = fresh.join("node_modules").join(".bin");
    let linked = std::fs::read_dir(&bin_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().starts_with(SCOPED_BIN))
        })
        .unwrap_or(false);
    assert!(
        linked,
        "bun must link the scoped package's `bin` from the 3-tuple meta under {}",
        bin_dir.display()
    );
}

/// Step 4, shared: the fresh-checkout frozen install MUST land the patched
/// bytes (BN7); then the ORDINARY install (node_modules removed, another
/// empty cache, plain `bun install`) MUST leave the committed lock
/// byte-identical and land the patched bytes again. Frozen mode never
/// writes the lock, so only the plain install can observe a
/// re-serialization of the local-tarball tuple — the property the module
/// doc calls BN3 and the backtest checks as `ordinaryStableLock`.
fn fresh_checkout_install_proof(fx: &BunProject, name: &str) {
    let (fresh, ci) = fresh_frozen_install(fx, name);
    assert!(
        ci.status.success(),
        "fresh-checkout `bun install --frozen-lockfile` must succeed from the vendored \
         tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed_index = fx.target.installed_dir(&fresh).join("index.js");
    let fresh_installed = std::fs::read(&installed_index).unwrap();
    assert!(
        fresh_installed.starts_with(MARKER.as_bytes()),
        "bun must install the PATCHED bytes from the vendored tarball; got:\n{}",
        String::from_utf8_lossy(&fresh_installed[..fresh_installed.len().min(120)])
    );
    assert_eq!(
        fresh_installed, fx.patched,
        "fresh install must be byte-identical to the patched content"
    );
    if fx.target == Target::ScopedWithDeps {
        assert_scoped_meta_honored(&fresh);
    }
    eprintln!("FRESH INSTALL OK ({name}, {:?})", fx.target);

    // Ordinary install: the lock must survive bun's own re-serialization.
    let wired_lock = std::fs::read(fx.proj.join("bun.lock")).unwrap();
    std::fs::remove_dir_all(fresh.join("node_modules")).unwrap();
    let plain_cache = fx.tmp.path().join(format!("{name}-plain-bun-cache"));
    let plain = bun(&fresh, &["install", "--ignore-scripts"], &plain_cache);
    assert!(
        plain.status.success(),
        "plain `bun install` on the vendored lock must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&plain.stdout),
        String::from_utf8_lossy(&plain.stderr),
    );
    assert_eq!(
        std::fs::read(fresh.join("bun.lock")).unwrap(),
        wired_lock,
        "an ORDINARY `bun install` must leave the vendored bun.lock byte-identical \
         (re-serialization drift would churn every commit)"
    );
    assert_eq!(
        std::fs::read(&installed_index).unwrap(),
        fx.patched,
        "the ordinary install must land the patched bytes too"
    );
    if fx.target == Target::ScopedWithDeps {
        assert_scoped_meta_honored(&fresh);
    }
    eprintln!("PLAIN INSTALL LOCK-STABLE ({name})");
}

/// The tampered twin's shared tail: bun.lock pins OUR sha512 while the
/// committed tarball now holds different bytes. Which outcome is correct
/// depends on the bun: from 1.3.10 the fresh frozen install MUST fail on
/// the integrity check; before it bun never verifies local-tarball digests
/// and MUST install the tampered bytes with exit 0 (reported PARTIAL — the
/// rejection proof is not available on that release, by bun's design).
fn assert_tamper_outcome(fx: &BunProject, tampered: &[u8]) {
    let (fresh, ci) = fresh_frozen_install(fx, "fresh-tampered");
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr)
    );
    if fx.bun_version >= TARBALL_INTEGRITY_ENFORCED_FROM {
        assert!(
            !ci.status.success(),
            "bun {} install MUST fail when the vendored tarball does not match the pinned \
             sha512 (digests are enforced from 1.3.10).\n{chatter}",
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
            "bun {} (< 1.3.10) does not verify local-tarball digests, so the tampered \
             install must still exit 0 — a failure here means the boundary moved.\n{chatter}",
            fx.bun_raw
        );
        let installed = std::fs::read(fx.target.installed_dir(&fresh).join("index.js")).unwrap();
        assert_eq!(
            installed, tampered,
            "bun {} installed neither the tampered bytes nor failed: the boundary model is wrong",
            fx.bun_raw
        );
        println!(
            "PARTIAL e2e_vendor_bun_build (tampered): bun {} does not verify local tarball \
             digests (enforced from 1.3.10) — rejection proof unavailable, acceptance pinned",
            fx.bun_raw
        );
    }
}

/// Steps 2–3 for the manifest-driven legs: stage the patch, `vendor
/// --offline`, assert the envelope and the on-disk vendored state.
fn stage_and_vendor(fx: &BunProject) {
    stage_patch(fx);
    let (code, stdout, stderr) = run_vendor(fx, &[]);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");
    let purl = fx.target.purl();
    let applied = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "applied" && e["purl"] == purl)
        .unwrap_or_else(|| panic!("expected an applied event for {purl}: {env}"));
    assert!(
        applied.get("errorCode").is_none(),
        "clean apply event: {applied}"
    );
    assert_vendored_on_disk(fx);
    eprintln!(
        "VENDOR OK (bun {}, lockfileVersion {}, {:?})",
        fx.bun_raw, fx.lock_version, fx.target
    );
}

// ── the capstone ──────────────────────────────────────────────────────

// #[serial]: each fresh install gets its own empty cache dir, but bun also
// keeps state under the sandboxed `~/.bun`; serializing keeps the tampered
// twin (same local tarball spec, different bytes) from ever racing a
// sibling's honest install.
#[test]
#[serial_test::serial]
fn bun_vendor_fresh_checkout_frozen_install_and_revert() {
    let Some(fx) = bun_project("vendor-offline", Target::LeftPad, None) else {
        return;
    };
    let proj = &fx.proj;
    let lock_path = proj.join("bun.lock");
    let pkg_path = proj.join("package.json");

    // 2–3. Hand-stage the .socket/ manifest + blob, vendor (offline).
    stage_and_vendor(&fx);

    // 4. FRESH-CHECKOUT PROOF: committable files only, EMPTY cache,
    //    spike-proven `--frozen-lockfile`, then the ordinary-install
    //    lock-stability twin.
    fresh_checkout_install_proof(&fx, "fresh");

    // 5. REPAIR PROOF: the committed artifact dir vanishes (a botched merge,
    //    an over-eager clean); `repair --offline` must rebuild the tarball
    //    byte-identically from the installed copy + blob, leave bun.lock
    //    alone, and a cold fresh checkout must install the marker bytes
    //    from the rebuilt artifact.
    let tgz_path = vendored_tgz(&fx);
    let tgz_bytes = std::fs::read(&tgz_path).unwrap();
    let lock_wired = std::fs::read(&lock_path).unwrap();
    std::fs::remove_dir_all(vendored_dir(proj)).unwrap();
    assert!(!tgz_path.exists(), "precondition: the vendored dir is gone");
    let (code, stdout, stderr) = run_socket(
        proj,
        &[
            "repair",
            "--json",
            "--offline",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "repair failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "repair envelope: {renv}");
    assert_eq!(
        renv["summary"]["rebuilt"], 1,
        "repair must rebuild the one deleted artifact: {renv}"
    );
    assert!(
        renv["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == fx.target.purl()),
        "repair must report a rebuilt event for {}: {renv}",
        fx.target.purl()
    );
    assert_eq!(
        std::fs::read(&tgz_path).unwrap(),
        tgz_bytes,
        "the deterministic rebuild must reproduce the vendored tarball byte-for-byte"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "repair must not touch bun.lock"
    );
    eprintln!("REPAIR OK");
    fresh_checkout_install_proof(&fx, "fresh-repaired");

    // 6. Idempotency: a re-run exits 0 and leaves bun.lock byte-stable.
    let (code, stdout, stderr) = run_vendor(&fx, &[]);
    assert_eq!(
        code, 0,
        "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env2 = parse_envelope(&stdout);
    assert_eq!(env2["summary"]["failed"], 0, "re-run must not fail: {env2}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "re-vendor must leave bun.lock byte-identical"
    );

    // 7. REVERT PROOF: bun.lock restored byte-for-byte, artifacts gone.
    let (code, stdout, stderr) = run_vendor(&fx, &["--revert"]);
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        fx.lock_before,
        "revert must restore bun.lock byte-identical to the pre-vendor snapshot"
    );
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        fx.pkg_before,
        "revert must leave package.json byte-identical"
    );
    assert!(
        !proj.join(".socket").join("vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
    eprintln!("REVERT OK");
}

// ── the scoped, dependency-bearing leg ────────────────────────────────

/// Scoped target with `dependencies` + `bin`: the vendored rewrite must
/// carry bun's meta object verbatim into the local-tarball 3-tuple (path
/// keeping the scope dir), leave the dependency's own registry entry
/// alone, and the fresh install must prove bun honored that meta —
/// left-pad installed, the bin linked — on top of the patched bytes and
/// the stable lock.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_vendor_scoped_package_keeps_deps_and_bin_meta() {
    let server = MockServer::start().await;
    mount_scoped_registry(&server, scoped_registry_tgz()).await;
    let Some(fx) = bun_project(
        "scoped-with-deps",
        Target::ScopedWithDeps,
        Some(&server.uri()),
    ) else {
        return;
    };
    stage_and_vendor(&fx);
    fresh_checkout_install_proof(&fx, "fresh");
}

// ── the tampered twin ─────────────────────────────────────────────────

/// Negative twin: the committed tarball is swapped for a DIFFERENT valid
/// tarball while bun.lock keeps our sha512. From bun 1.3.10 the fresh frozen
/// install must refuse on the integrity check; earlier bun installs the
/// tampered bytes with exit 0 and the leg pins THAT (PARTIAL), so the
/// digest boundary is asserted from both sides across the lock-era legs.
#[test]
#[serial_test::serial]
fn bun_vendor_tampered_tarball_digest_boundary() {
    let Some(fx) = bun_project("tampered", Target::LeftPad, None) else {
        return;
    };
    stage_and_vendor(&fx);

    // Tamper: a valid tarball with different content under the same path.
    // The lock still pins the sha512 of OUR tarball.
    let tampered: Vec<u8> = [TAMPER_MARKER.as_bytes(), fx.orig.as_slice()].concat();
    let tampered_tgz = make_tgz_from_installed(&fx.target.installed_dir(&fx.proj), &tampered);
    let tgz_path = vendored_tgz(&fx);
    assert_ne!(
        std::fs::read(&tgz_path).unwrap(),
        tampered_tgz,
        "the replacement tarball must differ from the vendored one"
    );
    std::fs::write(&tgz_path, &tampered_tgz).unwrap();

    assert_tamper_outcome(&fx, &tampered);
}

// ── the get-driven twin (v3.6) ────────────────────────────────────────

/// `view/{uuid}` carrying the SAME hashes the stager computes plus base64
/// `blobContent` of the after bytes — everything the get-vendored flow needs
/// to record the manifest and stage the patched content in memory (no
/// `.socket/blobs` is ever written).
async fn mock_view(server: &MockServer, purl: &str, before: &[u8], after: &[u8]) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": git_sha256(before),
                    "afterHash": git_sha256(after),
                    "blobContent": b64(after),
                }
            },
            "vulnerabilities": {},
            "description": "capstone marker patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

/// get-driven twin: `get <uuid> --mode vendored` must land scan's vendored
/// result — manifest record + committed artifact + ledger + wired lock, NO
/// blobs — and the fresh-checkout install proof must materialize the
/// patched bytes. The revert half is deliberately not repeated here:
/// `vendor --revert` on the capstone above already proves it (same ledger,
/// same engine).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_get_uuid_vendored_fresh_checkout_frozen_install() {
    let Some(fx) = bun_project("get-uuid-vendored", Target::LeftPad, None) else {
        return;
    };
    let proj = &fx.proj;
    let purl = fx.target.purl();

    // Steps 2–3, get-driven: the patch record comes from a mocked
    // `view/{uuid}` instead of a hand-staged `.socket/`, and the vendor step
    // builds the artifact locally (`--vendor-source build` — no vendoring
    // service, so no grant/tarball mocks are needed).
    let server = MockServer::start().await;
    mock_view(&server, purl, &fx.orig, &fx.patched).await;

    let server_uri = server.uri();
    let (code, stdout, stderr) = run_socket(
        proj,
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
            "--api-token",
            "fake",
            "--org",
            ORG,
            "--vendor-source",
            "build",
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
    assert!(
        env.get("applied").is_none(),
        "vendored get drops the applied key (nothing is applied in place): {env}"
    );
    assert_eq!(
        env["vendor"]["summary"]["applied"], 1,
        "the nested vendor envelope must report the one vendored package: {env}"
    );
    assert_eq!(
        env["vendor"]["summary"]["failed"], 0,
        "no vendor failures: {env}"
    );

    // Anti-vacuity oracle: the record really came from the mocked view
    // endpoint, not from any pre-existing local state.
    let view_hits = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().contains(&format!("/patches/view/{UUID}")))
        .count();
    assert!(
        view_hits >= 1,
        "the view endpoint must have served the patch record"
    );

    // Manifest yes, blobs no (scan-vendored parity: content stays in memory).
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(proj.join(".socket").join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["patches"][purl]["uuid"], UUID,
        "the manifest must record the vendored patch: {manifest}"
    );
    assert!(
        !proj.join(".socket").join("blobs").exists(),
        "get --mode vendored must NOT persist blobs"
    );

    assert_vendored_on_disk(&fx);
    eprintln!("GET VENDOR OK");

    // FRESH-CHECKOUT PROOF: committable files only, EMPTY cache,
    // spike-proven `--frozen-lockfile`, then the ordinary-install twin.
    fresh_checkout_install_proof(&fx, "fresh");
}

// ── digest-dropping lock re-saves (Bun 1.1.39–1.3.9) ─────────────────

/// A local `file:` tarball dep (`local-dep-<n>`) added to package.json plus
/// this bun's ordinary install: the one network-free way to make bun
/// RE-SAVE an existing lock. Returns the tarball file name, which every
/// fresh checkout below must carry along.
fn grow_project_with_local_dep(fx: &BunProject, n: u32) -> String {
    let name = format!("local-dep-{n}");
    let tgz_name = format!("{name}-1.0.0.tgz");
    let tgz = build_tgz(&[
        (
            "package.json".to_string(),
            format!(r#"{{"name":"{name}","version":"1.0.0"}}"#).into_bytes(),
            0o644,
        ),
        (
            "index.js".to_string(),
            b"module.exports = 'local';\n".to_vec(),
            0o644,
        ),
    ]);
    std::fs::write(fx.proj.join(&tgz_name), tgz).unwrap();
    let pkg_path = fx.proj.join("package.json");
    let mut pkg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pkg_path).unwrap()).unwrap();
    pkg["dependencies"][&name] = serde_json::json!(format!("file:./{tgz_name}"));
    std::fs::write(&pkg_path, serde_json::to_vec_pretty(&pkg).unwrap()).unwrap();
    let cache = fx.tmp.path().join(format!("resave-{n}-bun-cache"));
    let out = bun(&fx.proj, &fixture_install_args(fx.bun_version), &cache);
    assert!(
        out.status.success(),
        "`bun install` after adding {name} must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lock = std::fs::read_to_string(fx.proj.join("bun.lock")).unwrap();
    assert!(
        lock.contains(&format!("\"{name}\": [")),
        "the re-save must have landed {name}'s entry:\n{lock}"
    );
    tgz_name
}

/// The re-saved line must be the recorded 3-tuple (bun ≥ 1.3.10) or its
/// digest-less 2-tuple (below) — asserted per era, never guessed.
fn assert_resave_shape(fx: &BunProject, wired_line: &str) -> String {
    let live = packages_line(
        &std::fs::read_to_string(fx.proj.join("bun.lock")).unwrap(),
        fx.target.name(),
    );
    let digestless = format!(
        "{}],",
        &wired_line[..wired_line.rfind(", \"sha512-").unwrap()]
    );
    if fx.bun_version < TARBALL_INTEGRITY_ENFORCED_FROM {
        assert_eq!(
            live, digestless,
            "bun {} (< 1.3.10) must re-save the local tuple WITHOUT its sha512",
            fx.bun_raw
        );
    } else {
        assert_eq!(
            live, wired_line,
            "bun {} (>= 1.3.10) must keep the local tuple's sha512 on re-save",
            fx.bun_raw
        );
    }
    live
}

/// `bun install --frozen-lockfile` in a fresh checkout carrying the grown
/// project's local tarballs; returns the installed target `index.js`.
fn fresh_frozen_install_with_local_deps(fx: &BunProject, name: &str, tgzs: &[String]) -> Vec<u8> {
    let fresh = fresh_checkout(fx, name);
    for tgz in tgzs {
        std::fs::copy(fx.proj.join(tgz), fresh.join(tgz)).unwrap();
    }
    let cache = fx.tmp.path().join(format!("{name}-bun-cache"));
    let ci = bun(
        &fresh,
        &["install", "--frozen-lockfile", "--ignore-scripts"],
        &cache,
    );
    assert!(
        ci.status.success(),
        "fresh-checkout `bun install --frozen-lockfile` ({name}) must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr)
    );
    std::fs::read(fx.target.installed_dir(&fresh).join("index.js")).unwrap()
}

/// Every text-lock bun below 1.3.10 re-saves our local-tarball 3-tuple
/// WITHOUT its sha512 whenever the lock is re-saved for another reason
/// (measured on 1.1.45, 1.2.23 and 1.3.9; 1.3.10+ keep it). The 2-tuple is
/// still our wiring, so after a real re-save: the `vendor` re-run must stay
/// a clean no-op that heals the digest, `repair` must rebuild a deleted
/// artifact through it and re-pin the digest, a fresh frozen install must
/// land the patched bytes, and — after bun drops the digest AGAIN —
/// `vendor --revert` must restore the registry line inside the grown lock.
/// On ≥ 1.3.10 the same steps are the no-regression twin (digest kept).
#[test]
#[serial_test::serial]
fn bun_vendor_survives_a_digest_dropping_lock_resave() {
    let Some(fx) = bun_project("vendor-digestless-resave", Target::LeftPad, None) else {
        return;
    };
    let proj = &fx.proj;
    let lock_path = proj.join("bun.lock");
    stage_and_vendor(&fx);
    let wired_line = packages_line(&std::fs::read_to_string(&lock_path).unwrap(), DEP);
    assert!(wired_line.contains("\"sha512-"), "{wired_line}");

    // 1. Grow → re-save; assert the era's spelling.
    let tgz_a = grow_project_with_local_dep(&fx, 1);
    assert_resave_shape(&fx, &wired_line);
    eprintln!("RESAVE OK (bun {})", fx.bun_raw);

    // 2. Re-run `vendor`: exit 0, nothing failed, in sync, digest healed.
    let (code, stdout, stderr) = run_vendor(&fx, &[]);
    assert_eq!(
        code, 0,
        "re-vendor over the re-saved lock failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "{env}");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    assert!(
        env["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["errorCode"] != "vendor_lock_entry_not_found" && e["action"] != "failed"),
        "{env}"
    );
    let healed = std::fs::read_to_string(&lock_path).unwrap();
    assert_eq!(
        packages_line(&healed, DEP),
        wired_line,
        "the re-run must leave the canonical local 3-tuple in place:\n{healed}"
    );
    eprintln!("RE-VENDOR OK");

    // 3. Repair through a digest-less line: drop the digest again, delete
    //    the artifact, rebuild.
    let tgz_b = grow_project_with_local_dep(&fx, 2);
    assert_resave_shape(&fx, &wired_line);
    std::fs::remove_dir_all(vendored_dir(proj)).unwrap();
    let (code, stdout, stderr) = run_socket(
        proj,
        &[
            "repair",
            "--json",
            "--offline",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "repair failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "{renv}");
    assert_eq!(renv["summary"]["rebuilt"], 1, "{renv}");
    assert!(vendored_tgz(&fx).is_file(), "the artifact must be rebuilt");
    let repaired = std::fs::read_to_string(&lock_path).unwrap();
    assert_eq!(
        packages_line(&repaired, DEP),
        wired_line,
        "repair re-pins the digest into the healed 3-tuple:\n{repaired}"
    );
    eprintln!("REPAIR THROUGH DIGEST-LESS LOCK OK");

    // 4. The repaired lock installs the patched bytes from an empty cache.
    let installed = fresh_frozen_install_with_local_deps(
        &fx,
        "fresh-repaired",
        &[tgz_a.clone(), tgz_b.clone()],
    );
    assert_eq!(
        installed, fx.patched,
        "the repaired lock must install the patched bytes"
    );

    // 5. Drop the digest once more, then revert straight over it.
    let tgz_c = grow_project_with_local_dep(&fx, 3);
    assert_resave_shape(&fx, &wired_line);
    let (code, stdout, stderr) = run_vendor(&fx, &["--revert"]);
    assert_eq!(
        code, 0,
        "revert over the re-saved lock failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "{renv}");
    assert_eq!(renv["summary"]["removed"], 1, "{renv}");
    let restored = std::fs::read_to_string(&lock_path).unwrap();
    let lock_before = String::from_utf8(fx.lock_before.clone()).unwrap();
    assert_eq!(
        packages_line(&restored, DEP),
        packages_line(&lock_before, DEP),
        "the pristine registry 4-tuple must be back:\n{restored}"
    );
    for n in 1..=3 {
        assert!(
            restored.contains(&format!("\"local-dep-{n}\": [")),
            "revert must not disturb the grown entries:\n{restored}"
        );
    }
    assert!(
        !proj.join(".socket").join("vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
    let installed =
        fresh_frozen_install_with_local_deps(&fx, "fresh-reverted", &[tgz_a, tgz_b, tgz_c]);
    assert_eq!(
        installed, fx.orig,
        "after revert bun installs the ORIGINAL bytes"
    );
    eprintln!("REVERT AFTER RESAVE OK (bun {})", fx.bun_raw);
}
