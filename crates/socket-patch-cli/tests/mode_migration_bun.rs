//! Real-bun mode-migration e2e: hosted ⇄ vendored takeovers on a bun
//! (text `bun.lock`) project must leave the project FULLY in the new mode,
//! preview exactly what the wet run does, and unwind — scoped or whole —
//! back to the pristine registry lock.
//!
//! Twin of `mode_migration_npm.rs` (yarn classic + berry) and
//! `mode_migration_cargo.rs` for the one npm-family lock flavor whose
//! hosted rewrite REPLACES the entry's `name@version` spec: the registry
//! 4-tuple `["left-pad@1.3.0", "", {}, "sha512-…"]` becomes the URL 3-tuple
//! `["left-pad@https://…/left-pad-1.3.0.tgz", {}, "sha512-…"]`, so the
//! per-purl revert cannot key the edit by `name@version` the way the
//! yarn/pnpm/package-lock reverts do. Until the per-purl bun claim landed,
//! `vendor` / `scan --mode vendored` over a live hosted bun redirect was a
//! hard `redirect_revert_failed` refusal (with a circular remedy), a
//! scoped `rollback <purl>` / `remove <purl>` on a project holding two
//! hosted records failed the same way, and `vendor --dry-run` promised a
//! takeover the wet run refused. The hermetic (no-bun) contract twin is
//! `in_process_vendor_bun_takeover.rs`; THIS suite proves the same
//! contract against REAL bun, ending every terminal state with the proof
//! that matters — a fresh checkout's `bun install --frozen-lockfile` from
//! an EMPTY cache materializes the bytes the lock claims.
//!
//! Fixture: `package.json` with two real registry deps, `left-pad@1.3.0`
//! (the patched target) and `is-number@7.0.0` (dependency-free; the
//! untouched bystander in the single-patch legs, the second hosted record
//! in the scoped-unwind leg), installed by REAL `bun install
//! --ignore-scripts` (network for the fixture install only; a private
//! `BUN_INSTALL` + `BUN_INSTALL_CACHE_DIR` per project). The text lock is
//! the default from bun 1.2.0 (lockfileVersion 1; 2 from 1.4.0); on
//! 1.1.39–1.1.x the fixture passes the `--save-text-lockfile` opt-in
//! (lockfileVersion 0). The version bun wrote is ASSERTED against that
//! era table, so a lock-era CI leg proves the era it claims. Registry
//! 4-tuples are one emitted grammar across 0/1/2, so everything after the
//! fixture guard is version-independent. Patched tarballs are built from
//! the installed bytes (marker comment prepended to `index.js`) exactly
//! like the yarn twin; the patch API is wiremock (the bun rewriter needs
//! `artifacts[kind=tarball].integrity.sha512` from the grant, and the
//! `view/{uuid}` route carries `blobContent` so `scan --mode vendored` can
//! stage the patched content).
//!
//! Scenarios:
//!   1. vendored → hosted (`vendor --offline`, then `scan --mode hosted`):
//!      `redirect_takeover_reverted_vendored`, vendored ledger entry +
//!      committed artifact gone, bun.lock = the hosted URL 3-tuple with no
//!      `.socket/vendor/` residue, the redirect ledger's `original` is the
//!      PRISTINE registry line (originals chain intact across migrations),
//!      fresh frozen install → marker bytes; `rollback` → pristine bytes,
//!      no vendor artifacts or ledgers, fresh install → original bytes.
//!   2. hosted → vendored, BOTH drivers on copies of one hosted project:
//!      `vendor --offline` (staged manifest) and `scan --mode vendored`:
//!      `vendor_takeover_reverted_redirect`, redirect ledger record + edit
//!      dropped (file removed when emptied), bun.lock carries the local
//!      `.socket/vendor/npm/<uuid>/` 3-tuple and not the hosted URL, the
//!      vendor ledger's `original` is the pristine registry line, fresh
//!      frozen install → marker bytes; `vendor --revert` → pristine bytes.
//!   3. dry-run parity: over a live hosted redirect `vendor --dry-run`
//!      previews the takeover (`vendor_would_revert_redirect`, no false
//!      `vendor_lock_entry_not_found`, no refusal) and `scan --mode
//!      vendored --dry-run` classifies `would_vendor` (never `would_refuse`);
//!      over a live vendored state `scan --mode hosted --dry-run` previews
//!      `redirect_would_revert_vendored`; none of the previews writes a
//!      byte (bun.lock, both ledgers, every file under `.socket/`), and the
//!      wet runs then land exactly the takeovers previewed.
//!   4. two hosted records in ONE scan; scoped `rollback <purl-a>` and, on
//!      a fresh copy, `remove <purl-a>` (per-purl path — the whole-ledger
//!      replay is not eligible) unwind ONLY a's line/record/edit; a fresh
//!      frozen install lands a's ORIGINAL bytes and b's MARKER bytes; the
//!      unscoped `rollback` that follows restores the pristine lock.
//!   5. unscoped `rollback` from each mixed state — after (1) and after
//!      (2) — restores bun.lock byte-exactly, leaves no `.socket/vendor/`
//!      artifacts or ledgers, and a fresh install reproduces the original
//!      bytes.
//!
//! Gates (identical to `e2e_redirect_bun_build.rs` / `e2e_vendor_bun_build.rs`):
//! without `SOCKET_PATCH_BUN_E2E_REQUIRED` (set AND non-empty — CI passes
//! an empty string for non-bun legs) a missing `bun`, a failed fixture
//! install or a bun without a text lockfile is a `println` SKIP and every
//! assertion after that is HARD. With it, those skips become hard
//! failures, and `SOCKET_PATCH_BUN_E2E_VERSION` (when set, non-empty) must
//! equal `bun --version`, so a CI leg cannot pass by running the wrong bun
//! or no bun at all.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;

const SUITE: &str = "mode_migration_bun";
const ORG: &str = "test-org";
const TOKEN: &str = "33333333-3333-4333-8333-333333333333";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const GHSA: &str = "GHSA-migr-bun-test";

/// A fixture dependency and the two patch identities the legs use for it.
struct Dep {
    name: &'static str,
    version: &'static str,
    purl: &'static str,
    /// Vendored patch uuid: the manifest record `vendor --offline` acts on
    /// (the `.socket/vendor/npm/<uuid>/` path level of a manifest-driven
    /// vendor).
    uuid_v: &'static str,
    /// Hosted patch uuid: what the API mocks discover and grant (embedded in
    /// the hosted artifact URL), and therefore also the uuid a
    /// `scan --mode vendored` download records and vendors under.
    uuid_h: &'static str,
}

/// The patched target of every leg.
const DEP_A: Dep = Dep {
    name: "left-pad",
    version: "1.3.0",
    purl: "pkg:npm/left-pad@1.3.0",
    uuid_v: "3c4d5e6f-7a8b-4c1d-8e2f-0123456789ab",
    uuid_h: "8d9e0f1a-2b3c-4d4e-8f5a-6b7c8d9e0f1a",
};
/// The bystander (single-patch legs) / second hosted record (scoped leg).
const DEP_B: Dep = Dep {
    name: "is-number",
    version: "7.0.0",
    purl: "pkg:npm/is-number@7.0.0",
    uuid_v: "4d5e6f7a-8b9c-4d2e-9f3a-123456789abc",
    uuid_h: "9e0f1a2b-3c4d-4e5f-9a6b-7c8d9e0f1a2b",
};

impl Dep {
    /// `<name>-<version>.tgz` — the artifact leaf on the hosted URL and
    /// under the vendored dir.
    fn tgz_leaf(&self) -> String {
        format!("{}-{}.tgz", self.name, self.version)
    }
    /// The hosted tarball path on the mock patch server.
    fn hosted_path(&self) -> String {
        format!(
            "/patch/npm/{}/{}/{TOKEN}/{}/{}",
            self.name,
            self.version,
            self.uuid_h,
            self.tgz_leaf()
        )
    }
    fn hosted_url(&self, server_uri: &str) -> String {
        format!("{server_uri}{}", self.hosted_path())
    }
    /// The lock-relative local tarball path the vendored rewrite writes.
    fn vendored_rel(&self, uuid: &str) -> String {
        format!(".socket/vendor/npm/{uuid}/{}", self.tgz_leaf())
    }
    fn installed_dir(&self, proj: &Path) -> PathBuf {
        proj.join("node_modules").join(self.name)
    }
    /// The URL 3-tuple line the hosted rewriter writes for this dep (bun's
    /// `{}` meta for a dependency-free package; 4-space indent, trailing
    /// comma — the packages-entry grammar on lockfileVersion 0/1/2).
    fn hosted_line(&self, hosted_url: &str, sri: &str) -> String {
        format!(
            "    \"{}\": [\"{}@{hosted_url}\", {{}}, \"{sri}\"],",
            self.name, self.name
        )
    }
}

/// `(major, minor, patch)` of the bun on PATH.
type BunVersion = (u64, u64, u64);

/// First bun with a text lockfile (`--save-text-lockfile` opt-in,
/// lockfileVersion 0). Older bun writes only the binary `bun.lockb`.
const TEXT_LOCK_FROM: BunVersion = (1, 1, 39);
/// Text lock becomes the default and bumps to lockfileVersion 1.
const LOCK_V1_FROM: BunVersion = (1, 2, 0);
/// lockfileVersion 2.
const LOCK_V2_FROM: BunVersion = (1, 4, 0);

// ── toolchain gate (shared semantics with the two bun capstones) ──────────

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
    scrub_env(&mut probe);
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
/// neither dep has any, but the fixture is a REAL registry install), and
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
/// skips is exactly the vacuous pass the bun suites had for months.
fn bun_toolchain(tag: &str) -> Option<(String, BunVersion)> {
    let Some(raw) = bun_version_output() else {
        assert!(
            !bun_required(),
            "SOCKET_PATCH_BUN_E2E_REQUIRED is set but `bun --version` did not run — \
             the matrix leg must install bun before running this suite"
        );
        println!("SKIP {SUITE} ({tag}): `bun` not installed");
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
        println!("SKIP {SUITE} ({tag}): unparsable `bun --version` output {raw:?}");
        return None;
    };
    if version < TEXT_LOCK_FROM {
        assert!(
            !bun_required(),
            "bun {raw} has no text lockfile (the `--save-text-lockfile` opt-in exists from \
             1.1.39); a REQUIRED leg must not be scheduled on it"
        );
        println!("SKIP {SUITE} ({tag}): bun {raw} predates the text bun.lock (1.1.39)");
        return None;
    }
    Some((raw, version))
}

// ── process helpers ────────────────────────────────────────────────────────

/// Remove ambient `SOCKET_*` (except the hermetic `SOCKET_NO_CONFIG`),
/// every `BUN_*` var (the harness passes bun's install/cache dirs
/// explicitly per project), `npm_config_*` (bun reads npm's registry
/// config; an ambient mirror or auth token would change what the fixture
/// install resolves against) and `VIRTUAL_ENV` — the scrub the three bun
/// suites share, so none can drift back to a `SOCKET_*`-only scrub.
fn scrub_env(cmd: &mut Command) {
    cache_env::scrub_ambient_bun_env(cmd);
}

/// Run `bun <args>` in `cwd` with a PRIVATE `BUN_INSTALL` + cache under
/// `bun_home` (created here; a brand-new dir per call site is what makes
/// the fresh-checkout legs' "empty cache" premise true), the shared cache
/// sandbox for everything else bun keeps outside those dirs, and the
/// ambient env scrubbed. Scrub BEFORE seeding: `Command`'s last env call
/// for a name wins.
fn bun(cwd: &Path, args: &[&str], bun_home: &Path) -> Output {
    let cache = bun_home.join("cache");
    let install = bun_home.join("install");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::create_dir_all(&install).unwrap();
    let mut cmd = Command::new("bun");
    cmd.args(args).current_dir(cwd);
    scrub_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    cmd.env("BUN_INSTALL", &install)
        .env("BUN_INSTALL_CACHE_DIR", &cache);
    cmd.output().expect("failed to run bun")
}

/// The real binary with `--no-telemetry` appended: nothing in this suite
/// should ever post a telemetry event, mocked API or not.
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).arg("--no-telemetry").current_dir(cwd);
    scrub_env(&mut cmd);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Parse a `--json` envelope, or fail with the raw output attached.
fn envelope(stdout: &str, stderr: &str) -> Value {
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json output is not a JSON envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    })
}

fn hosted_scan(proj: &Path, api: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--json",
        "--yes",
        "--cwd",
        proj.to_str().unwrap(),
        "--api-url",
        api,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    args.extend_from_slice(extra);
    run_socket(proj, &args)
}

/// `scan --mode vendored` builds the artifact locally (`--vendor-source
/// build`): no vendoring-service round trip, so the only network is the
/// wiremock patch API.
fn vendored_scan(proj: &Path, api: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![
        "scan",
        "--mode",
        "vendored",
        "--json",
        "--yes",
        "--cwd",
        proj.to_str().unwrap(),
        "--api-url",
        api,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--vendor-source",
        "build",
    ];
    args.extend_from_slice(extra);
    run_socket(proj, &args)
}

/// `vendor --json --offline` (+ extra) over the staged manifest.
fn vendor_cmd(proj: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![
        "vendor",
        "--json",
        "--offline",
        "--cwd",
        proj.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run_socket(proj, &args)
}

/// `rollback [targets…] --yes --json`.
fn rollback_cmd(proj: &Path, targets: &[&str]) -> (i32, String, String) {
    let mut args = vec!["rollback"];
    args.extend_from_slice(targets);
    args.extend_from_slice(&["--yes", "--json", "--cwd", proj.to_str().unwrap()]);
    run_socket(proj, &args)
}

// ── bytes / files ──────────────────────────────────────────────────────────

fn sri(bytes: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn read(proj: &Path, rel: &str) -> String {
    std::fs::read_to_string(proj.join(rel)).unwrap_or_default()
}

fn read_json(proj: &Path, rel: &str) -> Value {
    let text = std::fs::read_to_string(proj.join(rel))
        .unwrap_or_else(|e| panic!("read {rel} under {}: {e}", proj.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{rel} is not JSON: {e}\n{text}"))
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

/// Every regular file under `root` (relative `/`-joined path → bytes),
/// `node_modules` excluded — the write-free oracle for the dry-run legs.
/// `.socket/apply.lock` is deliberately NOT excluded: every run removes its
/// lock file on exit (dry runs included), so a surviving one is a real
/// before/after difference.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "node_modules") {
                    continue;
                }
                walk(root, &p, out);
            } else {
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn assert_unchanged(before: &BTreeMap<String, Vec<u8>>, proj: &Path, what: &str) {
    let after = snapshot(proj);
    let added: Vec<&String> = after.keys().filter(|k| !before.contains_key(*k)).collect();
    let removed: Vec<&String> = before.keys().filter(|k| !after.contains_key(*k)).collect();
    let changed: Vec<&String> = before
        .iter()
        .filter(|(k, v)| after.get(*k).is_some_and(|a| a != *v))
        .map(|(k, _)| k)
        .collect();
    assert!(
        added.is_empty() && removed.is_empty() && changed.is_empty(),
        "{what} must not write a byte: added {added:?}, removed {removed:?}, changed {changed:?}"
    );
}

/// A gzipped npm tarball (`package/` prefix) built from the ACTUALLY
/// installed package with `index.js` swapped for `replaced_index`. Built
/// with the tar crate — no system `tar`, so Windows runners need nothing —
/// and file modes travel as installed (0o644/0o755 where the host has no
/// mode).
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
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(file_mode(p, &name));
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("package/{name}"), bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
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

/// The `packages` line for `name` in a bun.lock (`    "name": [...]`,
/// verbatim, no line terminator).
fn packages_line(lock: &str, name: &str) -> String {
    let key = format!("\"{name}\": [");
    lock.lines()
        .find(|l| l.trim_start().starts_with(&key))
        .unwrap_or_else(|| panic!("no packages entry for {name} in:\n{lock}"))
        .to_string()
}

/// The redirect ledger's `redirect_bun_lock_package` edit keyed by the
/// lock's package-map key (`name`), if any.
fn ledger_edit_for(ledger: &Value, name: &str) -> Option<Value> {
    ledger["edits"].as_array().and_then(|edits| {
        edits
            .iter()
            .find(|e| e["kind"] == "redirect_bun_lock_package" && e["key"] == name)
            .cloned()
    })
}

fn warning_codes(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|w| {
            w.iter()
                .filter_map(|x| x["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn event_codes(v: &Value) -> Vec<String> {
    v["events"]
        .as_array()
        .map(|evs| {
            evs.iter()
                .filter_map(|e| e["errorCode"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ── fixture ────────────────────────────────────────────────────────────────

/// The pristine and marker-patched `index.js` of one installed dep.
struct DepBytes {
    orig: Vec<u8>,
    patched: Vec<u8>,
}

/// The two-dep fixture project after a REAL `bun install`, plus the
/// pristine snapshots every unwind assertion diffs against.
struct Fixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    bun_raw: String,
    lock_version: u64,
    lock_pristine: Vec<u8>,
    pkg_json_pristine: Vec<u8>,
    a: DepBytes,
    b: DepBytes,
}

impl Fixture {
    fn lock_pristine_str(&self) -> String {
        String::from_utf8(self.lock_pristine.clone()).expect("bun.lock is UTF-8")
    }
    /// The pristine registry 4-tuple line for `dep`, verbatim.
    fn pristine_line(&self, dep: &Dep) -> String {
        packages_line(&self.lock_pristine_str(), dep.name)
    }
    fn bytes(&self, dep: &Dep) -> &DepBytes {
        if dep.name == DEP_A.name {
            &self.a
        } else {
            &self.b
        }
    }
    /// A fresh dir under the fixture tempdir.
    fn dir(&self, name: &str) -> PathBuf {
        let d = self.tmp.path().join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    /// The patched tarball for `dep`, from the fixture's installed copy.
    fn patched_tgz(&self, dep: &Dep) -> Vec<u8> {
        make_tgz_from_installed(&dep.installed_dir(&self.proj), &self.bytes(dep).patched)
    }
}

/// package.json + real install + era assertions. `None` = skip (already
/// reported), or a hard failure under the REQUIRED gate.
fn stage_fixture(tag: &str) -> Option<Fixture> {
    let (bun_raw, bun_version) = bun_toolchain(tag)?;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let pkg_json = format!(
        r#"{{"name":"mode-migration-bun","version":"0.0.0","private":true,"dependencies":{{"{}":"{}","{}":"{}"}}}}"#,
        DEP_A.name, DEP_A.version, DEP_B.name, DEP_B.version
    );
    std::fs::write(proj.join("package.json"), &pkg_json).unwrap();

    let bun_home = tmp.path().join("fixture-bun-home");
    let install = bun(&proj, &fixture_install_args(bun_version), &bun_home);
    if !install.status.success() {
        assert!(
            !bun_required(),
            "required bun {bun_raw} fixture `bun install` failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&install.stdout),
            String::from_utf8_lossy(&install.stderr)
        );
        println!(
            "SKIP {SUITE} ({tag}): fixture `bun install` failed (registry unreachable?):\n{}",
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
        println!("SKIP {SUITE} ({tag}): bun produced no text bun.lock (binary lockfile?)");
        return None;
    }
    // Hermeticity guard: the install must have gone through the PRIVATE
    // cache, or the fresh-checkout "empty cache" premise below is void.
    let cache = bun_home.join("cache");
    assert!(
        cache.is_dir() && std::fs::read_dir(&cache).unwrap().next().is_some(),
        "fixture install did not populate the private BUN_INSTALL_CACHE_DIR at {}",
        cache.display()
    );

    let lock_pristine = std::fs::read(&lock_path).unwrap();
    let lock_text = String::from_utf8(lock_pristine.clone()).expect("bun.lock is UTF-8");
    // The era table, asserted rather than assumed — pinning the mapping is
    // what makes a lock-era CI leg prove the era it claims to cover.
    let native_version = lock_version(&lock_text).unwrap_or_else(|| {
        panic!("fixture bun.lock has no integer lockfileVersion in its head:\n{lock_text}")
    });
    assert_eq!(
        native_version,
        expected_lock_version(bun_version),
        "bun {bun_raw} wrote lockfileVersion {native_version}; the era table expects {} \
         (1.1.39–1.1.x → 0, 1.2–1.3 → 1, ≥ 1.4 → 2):\n{lock_text}",
        expected_lock_version(bun_version)
    );
    let mut bytes: Vec<DepBytes> = Vec::new();
    for dep in [&DEP_A, &DEP_B] {
        // Pre-migration: the registry 4-tuple with bun's default-registry
        // `""` field and `{}` meta — one spelling across 0/1/2.
        let head = format!("\"{}@{}\", \"\", {{}}, \"sha512-", dep.name, dep.version);
        assert!(
            packages_line(&lock_text, dep.name).contains(&head),
            "pristine packages entry for {} must be the registry 4-tuple {head}…:\n{lock_text}",
            dep.name
        );
        let orig = std::fs::read(dep.installed_dir(&proj).join("index.js"))
            .unwrap_or_else(|e| panic!("installed {}/index.js: {e}", dep.name));
        assert!(
            !orig.starts_with(MARKER.as_bytes()),
            "pristine install of {} must not carry the marker",
            dep.name
        );
        let patched = [MARKER.as_bytes(), orig.as_slice()].concat();
        bytes.push(DepBytes { orig, patched });
    }
    let b = bytes.pop().unwrap();
    let a = bytes.pop().unwrap();
    eprintln!("FIXTURE OK (bun {bun_raw}, lockfileVersion {native_version}, {tag})");
    Some(Fixture {
        tmp,
        proj,
        bun_raw,
        lock_version: native_version,
        lock_pristine,
        pkg_json_pristine: pkg_json.into_bytes(),
        a,
        b,
    })
}

/// Copy a WORKING project (committable files + the installed tree) so two
/// drivers can start from one identical state without a second registry
/// install.
fn copy_project(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    std::fs::copy(from.join("package.json"), to.join("package.json")).unwrap();
    std::fs::copy(from.join("bun.lock"), to.join("bun.lock")).unwrap();
    if from.join(".socket").is_dir() {
        copy_dir_recursive(&from.join(".socket"), &to.join(".socket"));
    }
    copy_dir_recursive(&from.join("node_modules"), &to.join("node_modules"));
}

/// ONLY the committable files (package.json, bun.lock, `.socket/` when it
/// exists — rollback removes it) into a fresh dir: the fresh-checkout proof.
fn fresh_checkout(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    std::fs::copy(from.join("package.json"), to.join("package.json")).unwrap();
    std::fs::copy(from.join("bun.lock"), to.join("bun.lock")).unwrap();
    if from.join(".socket").is_dir() {
        copy_dir_recursive(&from.join(".socket"), &to.join(".socket"));
    }
}

/// Fresh checkout of `proj` named `name` + `bun install --frozen-lockfile
/// --ignore-scripts` against a brand-new (EMPTY) bun home; asserts success
/// and returns the checkout dir so callers probe the installed bytes.
fn fresh_frozen_install(fx: &Fixture, proj: &Path, name: &str) -> PathBuf {
    let fresh = fx.tmp.path().join(name);
    fresh_checkout(proj, &fresh);
    let ci = bun(
        &fresh,
        &["install", "--frozen-lockfile", "--ignore-scripts"],
        &fx.tmp.path().join(format!("{name}-bun-home")),
    );
    assert!(
        ci.status.success(),
        "fresh-checkout `bun install --frozen-lockfile` ({name}) must succeed.\nbun.lock:\n{}\n\
         stdout:\n{}\nstderr:\n{}",
        read(&fresh, "bun.lock"),
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    fresh
}

/// The installed `index.js` of `dep` in `root` must be exactly `expected`
/// (the marker-patched or the pristine bytes).
fn assert_installed(root: &Path, dep: &Dep, expected: &[u8], what: &str) {
    let installed = std::fs::read(dep.installed_dir(root).join("index.js"))
        .unwrap_or_else(|e| panic!("{what}: installed {}/index.js: {e}", dep.name));
    assert_eq!(
        installed,
        expected,
        "{what}: {} must install the {} bytes; got:\n{}",
        dep.name,
        if expected.starts_with(MARKER.as_bytes()) {
            "PATCHED (marker)"
        } else {
            "ORIGINAL"
        },
        String::from_utf8_lossy(&installed[..installed.len().min(120)])
    );
}

/// Write `.socket/manifest.json` + the after-hash blob for `dep` at
/// `uuid_v` so `vendor --offline` runs fully offline (npm-family file keys
/// carry the `package/` prefix). Hosted mode writes no manifest — its
/// ledger is its store — so this is the yarn twin's `stage_patch`.
fn stage_manifest(fx: &Fixture, proj: &Path, dep: &Dep) {
    let bytes = fx.bytes(dep);
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = json!({
        "patches": { dep.purl: {
            "uuid": dep.uuid_v,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": compute_git_sha256_from_bytes(&bytes.orig),
                "afterHash": compute_git_sha256_from_bytes(&bytes.patched),
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
    std::fs::write(
        socket
            .join("blobs")
            .join(compute_git_sha256_from_bytes(&bytes.patched)),
        &bytes.patched,
    )
    .unwrap();
}

/// One hosted patch the mock API serves: its tarball (built from the
/// installed bytes) and the hosted URL it lands on.
struct HostedPatch {
    dep: &'static Dep,
    tgz: Vec<u8>,
    url: String,
}

impl HostedPatch {
    fn sri(&self) -> String {
        sri(&self.tgz)
    }
}

/// Mount the full hosted-mode mock set for `deps` over one wiremock:
/// discovery (`batch`), the per-package detail query scan runs for EVERY
/// discovered package (`by-package/<encoded purl>` — matched per dep on
/// the name inside the encoded purl, so a two-record scan gets each dep's
/// own patch back), the grant (`package`, results for every uuid; the bun
/// rewriter needs `artifacts[kind=tarball].integrity.sha512`), the patch
/// view with `blobContent` (what `scan --mode vendored` stages from), and
/// the hosted tarball routes bun downloads at install time.
async fn mount_hosted_api(
    server: &MockServer,
    fx: &Fixture,
    deps: &[&'static Dep],
) -> Vec<HostedPatch> {
    let patches: Vec<HostedPatch> = deps
        .iter()
        .map(|dep| HostedPatch {
            dep,
            tgz: fx.patched_tgz(dep),
            url: dep.hosted_url(&server.uri()),
        })
        .collect();

    let batch_packages: Vec<Value> = patches
        .iter()
        .map(|p| {
            json!({
                "purl": p.dep.purl,
                "patches": [{
                    "uuid": p.dep.uuid_h, "purl": p.dep.purl, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": format!("bun migration fixture {}", p.dep.name)
                }]
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": batch_packages,
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;

    let mut results = serde_json::Map::new();
    for p in &patches {
        let dep = p.dep;
        let bytes = fx.bytes(dep);
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{}.*$",
                dep.name
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "patches": [{
                    "uuid": dep.uuid_h, "purl": dep.purl,
                    "publishedAt": "2026-01-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(server)
            .await;
        results.insert(
            dep.uuid_h.to_string(),
            json!({
                "status": "granted",
                "url": p.url,
                "purl": dep.purl,
                "artifacts": [{
                    "kind": "tarball", "url": p.url,
                    "integrity": { "sha512": p.sri() }
                }],
                "registryOverride": null
            }),
        );
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{}", dep.uuid_h)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": dep.uuid_h,
                "purl": dep.purl,
                "publishedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": compute_git_sha256_from_bytes(&bytes.orig),
                        "afterHash": compute_git_sha256_from_bytes(&bytes.patched),
                        "blobContent": b64(&bytes.patched),
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
            .and(path(dep.hosted_path()))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(p.tgz.clone(), "application/octet-stream"),
            )
            .mount(server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "results": Value::Object(results) })),
        )
        .mount(server)
        .await;
    patches
}

// ── shared state assertions ────────────────────────────────────────────────

/// `proj` is PURELY hosted for `hp.dep`: no vendored ledger claim, no
/// committed artifact (at either uuid), no `.socket/vendor/` residue in the
/// lock, the packages line IS the URL 3-tuple, and the redirect ledger's
/// record + edit are present with `original` == the PRISTINE registry line
/// and `new` == the live line. Every other dep's line is byte-identical to
/// the pristine lock.
fn assert_pure_hosted(fx: &Fixture, proj: &Path, hp: &HostedPatch) {
    let dep = hp.dep;
    let state = read(proj, ".socket/vendor/state.json");
    assert!(
        !state.contains(dep.purl),
        "the displaced vendored ledger entry must be dropped: {state}"
    );
    for stale in [dep.uuid_v, dep.uuid_h] {
        // The message deliberately names no identifier: CodeQL's
        // cleartext-logging heuristic treats anything flowing from a
        // `uuid`-named binding as sensitive.
        assert!(
            !proj.join(".socket/vendor/npm").join(stale).exists(),
            "every orphaned committed artifact dir under .socket/vendor/npm must be removed \
             after the hosted takeover"
        );
    }
    let lock = read(proj, "bun.lock");
    assert_eq!(
        packages_line(&lock, dep.name),
        dep.hosted_line(&hp.url, &hp.sri()),
        "bun.lock must carry the hosted URL 3-tuple for {}:\n{lock}",
        dep.name
    );
    assert!(
        !lock.contains(".socket/vendor/"),
        "no vendored residue may survive in the lock:\n{lock}"
    );
    assert_eq!(
        lock_version(&lock),
        Some(fx.lock_version),
        "the rewrite must keep the lock's own lockfileVersion line:\n{lock}"
    );
    for other in [&DEP_A, &DEP_B].into_iter().filter(|d| d.name != dep.name) {
        assert_eq!(
            packages_line(&lock, other.name),
            fx.pristine_line(other),
            "the un-patched {}'s registry 4-tuple must be byte-identical:\n{lock}",
            other.name
        );
    }
    let ledger = read_json(proj, ".socket/vendor/redirect-state.json");
    assert_eq!(
        ledger["records"][dep.purl]["uuid"], dep.uuid_h,
        "the redirect ledger must record the hosted patch: {ledger:#}"
    );
    let edit = ledger_edit_for(&ledger, dep.name).unwrap_or_else(|| {
        panic!(
            "no redirect_bun_lock_package edit for {}: {ledger:#}",
            dep.name
        )
    });
    assert_eq!(edit["path"], "bun.lock", "{edit:#}");
    assert_eq!(
        edit["original"],
        json!(fx.pristine_line(dep)),
        "the redirect ledger's `original` must be the PRISTINE registry line — never a \
         `.socket/vendor/` local-path line (originals chain intact across migrations): {edit:#}"
    );
    assert_eq!(
        edit["new"],
        json!(packages_line(&lock, dep.name)),
        "the redirect ledger's `new` must be the live lock line: {edit:#}"
    );
}

/// `proj` is PURELY vendored for `dep` at `uuid`: the redirect ledger no
/// longer claims the purl (record and edit both gone; file removed when
/// emptied), the packages line carries the local `.socket/vendor/npm/<uuid>/`
/// 3-tuple and no hosted URL, the artifact is committed, and the vendor
/// ledger's `bun_lock_package` wiring records the PRISTINE registry line as
/// its `original` (never the grant-tokenized hosted URL line). Every other
/// dep's line is byte-identical to the pristine lock.
fn assert_pure_vendored(fx: &Fixture, proj: &Path, dep: &Dep, uuid: &str, hosted_url: &str) {
    match std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")) {
        Ok(text) => {
            let ledger: Value = serde_json::from_str(&text).unwrap();
            assert!(
                ledger["records"].get(dep.purl).is_none(),
                "the superseded redirect record must be dropped: {ledger:#}"
            );
            assert!(
                ledger_edit_for(&ledger, dep.name).is_none(),
                "the superseded bun.lock edit must be dropped: {ledger:#}"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // An emptied ledger is deleted — the expected outcome when this
            // was the only hosted record.
        }
        Err(e) => panic!("unreadable redirect ledger: {e}"),
    }
    let lock = read(proj, "bun.lock");
    assert!(
        !lock.contains(hosted_url) && !lock.contains("/patch/npm/"),
        "the hosted URL must be gone from bun.lock:\n{lock}"
    );
    let rel = dep.vendored_rel(uuid);
    let line = packages_line(&lock, dep.name);
    assert!(
        line.starts_with(&format!(
            "    \"{}\": [\"{}@{rel}\", {{}}, \"sha512-",
            dep.name, dep.name
        )),
        "bun.lock must carry the local vendored 3-tuple for {}:\n{line}",
        dep.name
    );
    assert_eq!(
        lock_version(&lock),
        Some(fx.lock_version),
        "the rewrite must keep the lock's own lockfileVersion line:\n{lock}"
    );
    for other in [&DEP_A, &DEP_B].into_iter().filter(|d| d.name != dep.name) {
        assert_eq!(
            packages_line(&lock, other.name),
            fx.pristine_line(other),
            "the un-patched {}'s registry 4-tuple must be byte-identical:\n{lock}",
            other.name
        );
    }
    assert!(
        proj.join(&rel).is_file(),
        "the committed artifact tarball must exist under .socket/vendor/npm"
    );
    let state = read_json(proj, ".socket/vendor/state.json");
    let wiring = state["entries"][dep.purl]["wiring"]
        .as_array()
        .unwrap_or_else(|| panic!("wiring array for {}: {state:#}", dep.purl));
    let lock_wiring = wiring
        .iter()
        .find(|w| w["kind"] == "bun_lock_package")
        .unwrap_or_else(|| panic!("bun_lock_package wiring record: {state:#}"));
    assert_eq!(
        lock_wiring["original"],
        json!(fx.pristine_line(dep)),
        "the vendor ledger must record the PRISTINE registry line as its original (never \
         the grant-tokenized hosted URL line): {state:#}"
    );
    let state_text = read(proj, ".socket/vendor/state.json");
    assert!(
        !state_text.contains("/patch/npm/"),
        "the vendor ledger must NOT record the hosted fragment anywhere: {state_text}"
    );
}

/// After a full unwind: bun.lock and package.json byte-identical to the
/// pristine snapshots, and nothing left under `.socket/vendor/` — both
/// ledgers delete themselves when emptied and prune the emptied
/// `.socket/vendor/` dir (the redirect ledger's persist included, so a
/// `rollback` whose last act is the hosted unwind leaves no dir behind
/// either).
fn assert_pristine_unwound(fx: &Fixture, proj: &Path, what: &str) {
    assert_eq!(
        std::fs::read(proj.join("bun.lock")).unwrap(),
        fx.lock_pristine,
        "{what}: bun.lock must be byte-identical to the pristine registry lock; got:\n{}",
        read(proj, "bun.lock")
    );
    assert_eq!(
        std::fs::read(proj.join("package.json")).unwrap(),
        fx.pkg_json_pristine,
        "{what}: package.json must be untouched"
    );
    let vendor = proj.join(".socket/vendor");
    assert!(
        !vendor.join("state.json").exists() && !vendor.join("redirect-state.json").exists(),
        "{what}: no ledger may survive under .socket/vendor/"
    );
    assert!(
        !vendor.join("npm").exists(),
        "{what}: no committed artifact may survive under .socket/vendor/npm/"
    );
    assert!(
        !vendor.exists(),
        "{what}: the emptied .socket/vendor/ dir must be pruned"
    );
}

/// `rollback --yes --json` (unscoped) must exit 0 with `status: success`
/// and land the pristine state; a fresh frozen install then reproduces the
/// ORIGINAL bytes for every dep.
fn assert_unscoped_rollback_restores_pristine(fx: &Fixture, proj: &Path, tag: &str) {
    let (code, stdout, stderr) = rollback_cmd(proj, &[]);
    assert_eq!(code, 0, "rollback failed ({tag}): {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert_eq!(
        env["status"], "success",
        "rollback envelope ({tag}): {env:#}"
    );
    assert_eq!(
        env["hosted"]["failed"],
        json!([]),
        "rollback ({tag}) must not fail any hosted purl: {env:#}"
    );
    assert_pristine_unwound(fx, proj, &format!("rollback ({tag})"));
    let fresh = fresh_frozen_install(fx, proj, &format!("fresh-rolled-back-{tag}"));
    assert_installed(&fresh, &DEP_A, &fx.a.orig, "after rollback");
    assert_installed(&fresh, &DEP_B, &fx.b.orig, "after rollback");
    eprintln!("ROLLBACK OK ({tag}, bun {})", fx.bun_raw);
}

/// The vendored → hosted takeover on `proj` (already vendored for DEP_A at
/// `uuid_v`): `scan --mode hosted` must announce the takeover, leave the
/// project purely hosted, and a fresh frozen install from an empty cache
/// must land the MARKER bytes from the hosted tarball.
fn take_over_to_hosted(fx: &Fixture, proj: &Path, api: &str, hp: &HostedPatch, tag: &str) {
    let (code, stdout, stderr) = hosted_scan(proj, api, &[]);
    assert_eq!(code, 0, "hosted scan failed ({tag}): {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let codes = warning_codes(&env["redirect"]["warnings"]);
    assert!(
        codes
            .iter()
            .any(|c| c == "redirect_takeover_reverted_vendored"),
        "the takeover must be announced ({tag}): redirect.warnings codes = {codes:?}\n{env:#}"
    );
    assert!(
        !codes.iter().any(|c| c == "redirect_vendored_revert_failed"),
        "the vendored revert must not be refused ({tag}): {env:#}"
    );
    assert_pure_hosted(fx, proj, hp);
    let fresh = fresh_frozen_install(fx, proj, &format!("fresh-hosted-{tag}"));
    assert_installed(&fresh, &DEP_A, &fx.a.patched, "hosted fresh install");
    assert_installed(
        &fresh,
        &DEP_B,
        &fx.b.orig,
        "hosted fresh install (bystander)",
    );
    eprintln!("VENDORED→HOSTED OK ({tag}, bun {})", fx.bun_raw);
}

/// The hosted → vendored takeover on `proj` (already hosted for DEP_A),
/// driven by `driver`: the takeover must be announced, the project left
/// purely vendored at the uuid the driver vendors under, the vendor ledger
/// must hold that record (manifest-free for `scan --mode vendored`; the
/// manifest-fed `vendor` driver keeps its manifest record too), and a fresh
/// frozen install from an empty cache must land the MARKER bytes from the
/// committed artifact. Returns that uuid.
#[derive(Clone, Copy, PartialEq, Debug)]
enum VendoredDriver {
    /// `vendor --json --offline` over a hand-staged manifest (uuid_v).
    VendorOffline,
    /// `scan --mode vendored --json --yes` — discovery + download from the
    /// mock API (uuid_h), then the same vendor engine.
    ScanVendored,
}

fn take_over_to_vendored(
    fx: &Fixture,
    proj: &Path,
    api: &str,
    hp: &HostedPatch,
    driver: VendoredDriver,
    tag: &str,
) -> &'static str {
    let dep = hp.dep;
    // Kept apart from the envelope on purpose (no tuple): CodeQL's
    // cleartext-logging heuristic would otherwise taint every `{vendor_env}`
    // assertion message with the `uuid`-named half.
    let uuid = match driver {
        VendoredDriver::VendorOffline => dep.uuid_v,
        VendoredDriver::ScanVendored => dep.uuid_h,
    };
    let vendor_env = match driver {
        VendoredDriver::VendorOffline => {
            stage_manifest(fx, proj, dep);
            let (code, stdout, stderr) = vendor_cmd(proj, &[]);
            assert_eq!(code, 0, "vendor failed ({tag}): {stdout}\n{stderr}");
            envelope(&stdout, &stderr)
        }
        VendoredDriver::ScanVendored => {
            let (code, stdout, stderr) = vendored_scan(proj, api, &[]);
            assert_eq!(
                code, 0,
                "scan --mode vendored failed ({tag}): {stdout}\n{stderr}"
            );
            let env = envelope(&stdout, &stderr);
            assert_eq!(env["status"], "success", "{env:#}");
            env["vendor"].clone()
        }
    };
    assert_eq!(vendor_env["status"], "success", "{vendor_env:#}");
    assert_eq!(vendor_env["summary"]["applied"], 1, "{vendor_env:#}");
    assert_eq!(vendor_env["summary"]["failed"], 0, "{vendor_env:#}");
    let codes = event_codes(&vendor_env);
    assert!(
        codes
            .iter()
            .any(|c| c == "vendor_takeover_reverted_redirect"),
        "the takeover must be announced ({tag}, {driver:?}): event codes = {codes:?}\n\
         {vendor_env:#}"
    );
    assert!(
        !codes.iter().any(|c| c == "redirect_revert_failed"),
        "the hosted revert must not be refused ({tag}, {driver:?}): {vendor_env:#}"
    );
    assert_pure_vendored(fx, proj, dep, uuid, &hp.url);
    let state = read_json(proj, ".socket/vendor/state.json");
    assert_eq!(
        state["entries"][dep.purl]["uuid"], uuid,
        "the vendor ledger must record the vendored patch ({tag}, {driver:?}): {state:#}"
    );
    match driver {
        // Standalone `vendor` is fed by the staged manifest and leaves its
        // record in place — the legacy manifest-tracked shape.
        VendoredDriver::VendorOffline => {
            let manifest = read_json(proj, ".socket/manifest.json");
            assert_eq!(
                manifest["patches"][dep.purl]["uuid"], uuid,
                "the manifest must record the vendored patch ({tag}, {driver:?}): {manifest:#}"
            );
        }
        // Vendored mode is manifest-free: the ledger entry embeds the record
        // and nothing else is written under `.socket/`.
        VendoredDriver::ScanVendored => {
            assert_eq!(
                state["entries"][dep.purl]["detached"],
                json!(true),
                "scan --mode vendored writes a detached entry ({tag}): {state:#}"
            );
            assert_eq!(
                state["entries"][dep.purl]["record"]["uuid"], uuid,
                "the embedded record is the vendored patch ({tag}): {state:#}"
            );
            assert!(
                !proj.join(".socket/manifest.json").exists(),
                "scan --mode vendored must not write a manifest ({tag})"
            );
        }
    }
    let fresh = fresh_frozen_install(fx, proj, &format!("fresh-vendored-{tag}"));
    assert_installed(&fresh, &DEP_A, &fx.a.patched, "vendored fresh install");
    assert_installed(
        &fresh,
        &DEP_B,
        &fx.b.orig,
        "vendored fresh install (bystander)",
    );
    eprintln!("HOSTED→VENDORED OK ({tag}, {driver:?}, bun {})", fx.bun_raw);
    uuid
}

/// `vendor --revert` must restore the REGISTRY lock byte-identically (the
/// pre-redirect resolution the takeover carried forward, not the hosted
/// splice) and prune `.socket/vendor/`.
fn assert_vendor_revert_restores_pristine(fx: &Fixture, proj: &Path, tag: &str) {
    let (code, stdout, stderr) = vendor_cmd(proj, &["--revert"]);
    assert_eq!(
        code, 0,
        "vendor --revert failed ({tag}): {stdout}\n{stderr}"
    );
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(env["summary"]["removed"], 1, "{env:#}");
    assert_pristine_unwound(fx, proj, &format!("vendor --revert ({tag})"));
    eprintln!("VENDOR REVERT OK ({tag})");
}

// ─────────────────────────────────────────────────────────────────────────
// 1. vendored → hosted takeover leaves the project purely hosted
// ─────────────────────────────────────────────────────────────────────────

// #[serial]: bun keeps state under the sandboxed `~/.bun` besides the
// per-project cache dirs; serializing keeps legs that install the same
// hosted URL / local tarball spec from ever racing each other.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_vendored_then_hosted_takeover_leaves_pure_hosted() {
    let Some(fx) = stage_fixture("vendored-then-hosted") else {
        return;
    };
    let proj = fx.proj.clone();

    // A: vendor (offline) from the staged manifest.
    stage_manifest(&fx, &proj, &DEP_A);
    let (code, stdout, stderr) = vendor_cmd(&proj, &[]);
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["summary"]["applied"], 1, "{env:#}");
    assert!(
        read(&proj, ".socket/vendor/state.json").contains(DEP_A.purl),
        "the vendored ledger must claim the purl"
    );
    assert!(
        read(&proj, "bun.lock").contains(&DEP_A.vendored_rel(DEP_A.uuid_v)),
        "bun.lock must be vendored-wired before the takeover:\n{}",
        read(&proj, "bun.lock")
    );

    // B: hosted redirect over the vendored state — the takeover — then the
    //    fresh-checkout marker proof.
    let server = MockServer::start().await;
    let patches = mount_hosted_api(&server, &fx, &[&DEP_A]).await;
    take_over_to_hosted(&fx, &proj, &server.uri(), &patches[0], "rev");

    // C: unscoped rollback → pristine bytes, no vendor artifacts or
    //    ledgers, fresh install → original bytes.
    assert_unscoped_rollback_restores_pristine(&fx, &proj, "after-vendored-then-hosted");
}

// ─────────────────────────────────────────────────────────────────────────
// 2. hosted → vendored takeover round-trips to the registry (both drivers)
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_hosted_then_vendored_takeover_round_trips_to_registry() {
    let Some(fx) = stage_fixture("hosted-then-vendored") else {
        return;
    };
    let proj = fx.proj.clone();
    let server = MockServer::start().await;
    let patches = mount_hosted_api(&server, &fx, &[&DEP_A]).await;
    let hp = &patches[0];

    // A: hosted redirect: registry 4-tuple → URL 3-tuple, ledger claims the
    //    purl with one `redirect_bun_lock_package` edit whose original is
    //    the pristine registry line; a fresh frozen install lands the
    //    patched tree.
    let (code, stdout, stderr) = hosted_scan(&proj, &server.uri(), &[]);
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    assert_pure_hosted(&fx, &proj, hp);
    let fresh = fresh_frozen_install(&fx, &proj, "fresh-hosted");
    assert_installed(&fresh, &DEP_A, &fx.a.patched, "hosted fresh install");

    // B: BOTH vendored drivers, each on its own copy of the hosted project.
    let by_vendor = fx.dir("hosted-copy-vendor");
    copy_project(&proj, &by_vendor);
    let by_scan = fx.dir("hosted-copy-scan");
    copy_project(&proj, &by_scan);

    take_over_to_vendored(
        &fx,
        &by_vendor,
        &server.uri(),
        hp,
        VendoredDriver::VendorOffline,
        "vendor-offline",
    );
    assert_vendor_revert_restores_pristine(&fx, &by_vendor, "vendor-offline");

    take_over_to_vendored(
        &fx,
        &by_scan,
        &server.uri(),
        hp,
        VendoredDriver::ScanVendored,
        "scan-vendored",
    );
    // A re-run is an in-sync no-op with no second takeover.
    let (code, stdout, stderr) = vendored_scan(&by_scan, &server.uri(), &[]);
    assert_eq!(code, 0, "vendored re-run failed: {stdout}\n{stderr}");
    let rerun = envelope(&stdout, &stderr);
    let codes = event_codes(&rerun["vendor"]);
    assert!(
        codes.iter().any(|c| c == "already_vendored")
            && !codes
                .iter()
                .any(|c| c == "vendor_takeover_reverted_redirect"),
        "the re-run must be `already_vendored` with no second takeover: {codes:?}\n{rerun:#}"
    );
    assert_vendor_revert_restores_pristine(&fx, &by_scan, "scan-vendored");
}

// ─────────────────────────────────────────────────────────────────────────
// 3. dry-run previews match the wet outcomes, and write nothing
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_dry_run_previews_match_wet_outcomes() {
    let Some(fx) = stage_fixture("dry-run") else {
        return;
    };
    let proj = fx.proj.clone();
    let server = MockServer::start().await;
    let patches = mount_hosted_api(&server, &fx, &[&DEP_A]).await;
    let hp = &patches[0];
    let api = server.uri();

    // ── over a LIVE HOSTED redirect ──────────────────────────────────────
    let hosted = fx.dir("live-hosted");
    copy_project(&proj, &hosted);
    let (code, stdout, stderr) = hosted_scan(&hosted, &api, &[]);
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    assert_pure_hosted(&fx, &hosted, hp);
    // The manifest record `vendor` acts on (offline: the staged blob).
    stage_manifest(&fx, &hosted, &DEP_A);
    let before = snapshot(&hosted);

    // `vendor --dry-run`: the takeover is PROBED (write-free per-purl revert
    // on a ledger clone) and previewed; the backend preview does not run
    // against the still-hosted lock, so no false `vendor_lock_entry_not_found`
    // and no refusal.
    let (code, stdout, stderr) = vendor_cmd(&hosted, &["--dry-run"]);
    assert_eq!(code, 0, "vendor --dry-run must succeed: {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["dryRun"], true, "{env:#}");
    assert_eq!(env["summary"]["failed"], 0, "{env:#}");
    let advisory = env["events"]
        .as_array()
        .and_then(|evs| {
            evs.iter()
                .find(|e| e["errorCode"] == "vendor_would_revert_redirect")
        })
        .unwrap_or_else(|| panic!("expected a `vendor_would_revert_redirect` preview: {env:#}"));
    assert_eq!(advisory["action"], "skipped", "{advisory:#}");
    assert_eq!(advisory["purl"], DEP_A.purl, "{advisory:#}");
    let codes = event_codes(&env);
    for forbidden in ["vendor_lock_entry_not_found", "redirect_revert_failed"] {
        assert!(
            !codes.iter().any(|c| c == forbidden),
            "vendor --dry-run must not emit `{forbidden}` over a takeover it can perform: \
             {env:#}"
        );
    }
    assert_unchanged(&before, &hosted, "vendor --dry-run");

    // `scan --mode vendored --dry-run`: the scan-side preview is a ledger
    // classification by contract (`would_vendor` | `already_vendored` |
    // `would_revendor`, plus the additive Bun-preflight `would_refuse`); over
    // a takeover the wet run performs it must say `would_vendor` — never
    // `would_refuse`, never a refusal — and write nothing.
    let (code, stdout, stderr) = vendored_scan(&hosted, &api, &["--dry-run"]);
    assert_eq!(
        code, 0,
        "scan --mode vendored --dry-run must succeed: {stdout}\n{stderr}"
    );
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(env["vendor"]["dryRun"], true, "{env:#}");
    let preview = env["vendor"]["patches"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["purl"] == DEP_A.purl))
        .unwrap_or_else(|| {
            panic!(
                "expected a vendored preview record for {}: {env:#}",
                DEP_A.purl
            )
        });
    assert_eq!(
        preview["action"], "would_vendor",
        "the vendored preview over a live hosted bun redirect must classify `would_vendor` \
         (the wet run takes over and vendors): {env:#}"
    );
    assert!(
        !stdout.contains("redirect_revert_failed") && !stdout.contains("would_refuse"),
        "the vendored preview must not advertise a refusal the wet run never makes:\n{stdout}"
    );
    assert_unchanged(&before, &hosted, "scan --mode vendored --dry-run");

    // The WET vendor lands exactly the takeover previewed.
    let (code, stdout, stderr) = vendor_cmd(&hosted, &[]);
    assert_eq!(code, 0, "wet vendor failed: {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["summary"]["applied"], 1, "{env:#}");
    assert!(
        event_codes(&env)
            .iter()
            .any(|c| c == "vendor_takeover_reverted_redirect"),
        "the wet vendor must perform the takeover the preview promised: {env:#}"
    );
    assert_pure_vendored(&fx, &hosted, &DEP_A, DEP_A.uuid_v, &hp.url);

    // ── over a LIVE VENDORED state ───────────────────────────────────────
    let vendored = fx.dir("live-vendored");
    copy_project(&proj, &vendored);
    stage_manifest(&fx, &vendored, &DEP_A);
    let (code, stdout, stderr) = vendor_cmd(&vendored, &[]);
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    assert_pure_vendored(&fx, &vendored, &DEP_A, DEP_A.uuid_v, &hp.url);
    let before = snapshot(&vendored);

    // `scan --mode hosted --dry-run`: the vendored revert is probed
    // write-free and the takeover previewed; nothing is rewritten, no ledger
    // is written.
    let (code, stdout, stderr) = hosted_scan(&vendored, &api, &["--dry-run"]);
    assert_eq!(
        code, 0,
        "scan --mode hosted --dry-run must succeed: {stdout}\n{stderr}"
    );
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["redirect"]["dryRun"], true, "{env:#}");
    let codes = warning_codes(&env["redirect"]["warnings"]);
    assert!(
        codes.iter().any(|c| c == "redirect_would_revert_vendored"),
        "the hosted preview must announce the vendored takeover: {codes:?}\n{env:#}"
    );
    assert!(
        !codes.iter().any(|c| c == "redirect_vendored_revert_failed"),
        "the hosted preview must not refuse a takeover the wet run performs: {env:#}"
    );
    assert_unchanged(&before, &vendored, "scan --mode hosted --dry-run");

    // The WET hosted scan lands exactly the takeover previewed.
    take_over_to_hosted(&fx, &vendored, &api, hp, "after-dry-run");
}

// ─────────────────────────────────────────────────────────────────────────
// 4. scoped rollback / remove of ONE of two hosted records
// ─────────────────────────────────────────────────────────────────────────

/// After unwinding ONLY DEP_A: its line is the pristine registry tuple,
/// DEP_B is still hosted, the ledger keeps exactly DEP_B's record + edit,
/// and a fresh frozen install lands A's ORIGINAL and B's MARKER bytes.
fn assert_only_a_unwound(fx: &Fixture, proj: &Path, b: &HostedPatch, tag: &str) {
    let lock = read(proj, "bun.lock");
    assert_eq!(
        packages_line(&lock, DEP_A.name),
        fx.pristine_line(&DEP_A),
        "{tag}: {} must be back to its registry tuple:\n{lock}",
        DEP_A.name
    );
    assert_eq!(
        packages_line(&lock, DEP_B.name),
        DEP_B.hosted_line(&b.url, &b.sri()),
        "{tag}: {} must stay hosted:\n{lock}",
        DEP_B.name
    );
    let ledger = read_json(proj, ".socket/vendor/redirect-state.json");
    assert!(
        ledger["records"].get(DEP_A.purl).is_none(),
        "{tag}: A's record must be dropped: {ledger:#}"
    );
    assert_eq!(
        ledger["records"][DEP_B.purl]["uuid"], DEP_B.uuid_h,
        "{tag}: B's record must stay: {ledger:#}"
    );
    let edits = ledger["edits"].as_array().unwrap();
    assert_eq!(
        edits.len(),
        1,
        "{tag}: exactly B's edit must stay: {ledger:#}"
    );
    assert_eq!(edits[0]["key"], DEP_B.name, "{tag}: {ledger:#}");
    let fresh = fresh_frozen_install(fx, proj, &format!("fresh-{tag}"));
    assert_installed(&fresh, &DEP_A, &fx.a.orig, tag);
    assert_installed(&fresh, &DEP_B, &fx.b.patched, tag);
    eprintln!("SCOPED UNWIND OK ({tag}, bun {})", fx.bun_raw);
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_scoped_rollback_and_remove_unwind_one_of_two_hosted_records() {
    let Some(fx) = stage_fixture("scoped-unwind") else {
        return;
    };
    let proj = fx.proj.clone();
    let server = MockServer::start().await;
    let patches = mount_hosted_api(&server, &fx, &[&DEP_A, &DEP_B]).await;
    let (a, b) = (&patches[0], &patches[1]);

    // Both deps hosted-redirected in ONE scan: two records, two edits.
    let (code, stdout, stderr) = hosted_scan(&proj, &server.uri(), &[]);
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["redirect"]["redirected"], 2, "{env:#}");
    let lock = read(&proj, "bun.lock");
    for hp in [a, b] {
        assert_eq!(
            packages_line(&lock, hp.dep.name),
            hp.dep.hosted_line(&hp.url, &hp.sri()),
            "{} must be hosted:\n{lock}",
            hp.dep.name
        );
    }
    let ledger = read_json(&proj, ".socket/vendor/redirect-state.json");
    assert_eq!(
        ledger["records"].as_object().map(|m| m.len()),
        Some(2),
        "{ledger:#}"
    );
    assert_eq!(
        ledger["edits"].as_array().map(|e| e.len()),
        Some(2),
        "{ledger:#}"
    );
    for hp in [a, b] {
        let edit = ledger_edit_for(&ledger, hp.dep.name)
            .unwrap_or_else(|| panic!("no edit for {}: {ledger:#}", hp.dep.name));
        assert_eq!(
            edit["original"],
            json!(fx.pristine_line(hp.dep)),
            "{edit:#}"
        );
    }
    let fresh = fresh_frozen_install(&fx, &proj, "fresh-two-hosted");
    assert_installed(&fresh, &DEP_A, &fx.a.patched, "two hosted records");
    assert_installed(&fresh, &DEP_B, &fx.b.patched, "two hosted records");

    // Scoped rollback of A: per-purl path (two records ⇒ the whole-ledger
    // replay is not eligible). Used to exit 1 with hosted.failed = ["cannot
    // replay yet"].
    let by_rollback = fx.dir("two-hosted-copy-rollback");
    copy_project(&proj, &by_rollback);
    let (code, stdout, stderr) = rollback_cmd(&by_rollback, &[DEP_A.purl]);
    assert_eq!(code, 0, "scoped rollback must succeed: {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(env["hosted"]["reverted"], json!([DEP_A.purl]), "{env:#}");
    assert_eq!(env["hosted"]["failed"], json!([]), "{env:#}");
    assert_eq!(env["hosted"]["unsupported"], json!([]), "{env:#}");
    assert_only_a_unwound(&fx, &by_rollback, b, "scoped-rollback");
    // Then the unscoped rollback: covers the last record ⇒ whole-ledger
    // replay ⇒ pristine.
    assert_unscoped_rollback_restores_pristine(&fx, &by_rollback, "after-scoped-rollback");

    // `remove <purl>` takes the same per-purl hosted leg; used to exit 1
    // with `hosted_revert_failed`.
    let by_remove = fx.dir("two-hosted-copy-remove");
    copy_project(&proj, &by_remove);
    let (code, stdout, stderr) = run_socket(
        &by_remove,
        &[
            "remove",
            DEP_A.purl,
            "--yes",
            "--json",
            "--cwd",
            by_remove.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "scoped remove must succeed: {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert!(
        env["error"].is_null(),
        "remove must report no top-level error: {env:#}"
    );
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(env["summary"]["removed"], 1, "{env:#}");
    assert_eq!(env["summary"]["failed"], 0, "{env:#}");
    // The hosted unwind rides a `removed` event tagged `hosted_reverted`
    // (remove's per-purl hosted leg; a `hosted_revert_failed` top-level
    // error was the pre-fix shape).
    assert!(
        env["events"]
            .as_array()
            .is_some_and(|evs| evs.iter().any(|e| {
                e["action"] == "removed"
                    && e["errorCode"] == "hosted_reverted"
                    && e["purl"] == DEP_A.purl
            })),
        "remove must report the hosted unwind of {}: {env:#}",
        DEP_A.purl
    );
    assert_only_a_unwound(&fx, &by_remove, b, "scoped-remove");
    assert_unscoped_rollback_restores_pristine(&fx, &by_remove, "after-scoped-remove");
}

// ─────────────────────────────────────────────────────────────────────────
// 5. unscoped rollback from each mixed state restores pristine
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_rollback_from_each_mixed_state_restores_pristine() {
    let Some(fx) = stage_fixture("rollback-mixed") else {
        return;
    };
    let proj = fx.proj.clone();
    let server = MockServer::start().await;
    let patches = mount_hosted_api(&server, &fx, &[&DEP_A]).await;
    let hp = &patches[0];
    let api = server.uri();

    // State (1): vendored → hosted, then rollback. The manifest still holds
    // the vendored record the hosted takeover superseded; rollback's manifest
    // leg retires it alongside the hosted unwind.
    let one = fx.dir("mixed-vendored-then-hosted");
    copy_project(&proj, &one);
    stage_manifest(&fx, &one, &DEP_A);
    let (code, stdout, stderr) = vendor_cmd(&one, &[]);
    assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
    take_over_to_hosted(&fx, &one, &api, hp, "mixed-1");
    assert_unscoped_rollback_restores_pristine(&fx, &one, "mixed-1");

    // State (2): hosted → vendored (scan-driven), then rollback: the
    // vendored leg unwires + removes the artifact, the (emptied) redirect
    // ledger is already gone, the manifest record is retired.
    let two = fx.dir("mixed-hosted-then-vendored");
    copy_project(&proj, &two);
    let (code, stdout, stderr) = hosted_scan(&two, &api, &[]);
    assert_eq!(code, 0, "hosted scan failed: {stdout}\n{stderr}");
    take_over_to_vendored(&fx, &two, &api, hp, VendoredDriver::ScanVendored, "mixed-2");
    let (code, stdout, stderr) = rollback_cmd(&two, &[]);
    assert_eq!(code, 0, "rollback failed (mixed-2): {stdout}\n{stderr}");
    let env = envelope(&stdout, &stderr);
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(
        env["vendoredReverted"],
        json!([DEP_A.purl]),
        "rollback must unwire the vendored purl: {env:#}"
    );
    assert_eq!(env["vendoredFailed"], json!([]), "{env:#}");
    assert_pristine_unwound(&fx, &two, "rollback (mixed-2)");
    let fresh = fresh_frozen_install(&fx, &two, "fresh-rolled-back-mixed-2");
    assert_installed(&fresh, &DEP_A, &fx.a.orig, "after rollback (mixed-2)");
    assert_installed(&fresh, &DEP_B, &fx.b.orig, "after rollback (mixed-2)");
    eprintln!("ROLLBACK OK (mixed-2, bun {})", fx.bun_raw);
}
