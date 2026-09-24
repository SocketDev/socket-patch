//! Hermetic manifest-less VEX cells for pnpm — every lock era, no pnpm
//! binary, all three OSes, never `#[ignore]`d.
//!
//! The real-pnpm halves live in `e2e_redirect_pnpm_build.rs` (hosted) and
//! `e2e_vendor_pnpm_build.rs` (vendored): a real install per pinned pnpm
//! release, ending in the manifest-less VEX cells. This suite covers the
//! evidence edges a real install cannot stage, over the byte-real locks the
//! pnpm 1-12 matrix captured (`socket-patch-core/tests/fixtures/pnpm-hosted/
//! <version>/`: shrinkwrap 3 for pnpm 1-2, lockfileVersion 5.0-5.4 for 3-7,
//! 6.0 for 8, 9.0 for 9-12):
//!
//! * hosted — the REAL `scan --mode hosted` (wiremock patch API; the hosted
//!   URL is on `patch.socket.dev`, so no `--patch-server-url` is needed)
//!   rewrites the fixture lock over a stub installed tree; then, with the
//!   manifest AND both ledgers deleted:
//!   - installed + patched attests `(redirected)`;
//!   - installed but tampered is omitted (`hash_mismatch`);
//!   - installed but pristine is omitted (`not_applied`);
//!   - not installed attests from the lock's integrity-pinned wiring;
//!   - a record naming another package, or another patch, is omitted
//!     (`record_mismatch`);
//!   - `--offline` is omitted (`record_unavailable`) with zero requests;
//!   - the same uuid-shaped URL on a non-Socket host is not a reference at
//!     all — nothing to attest, and no request is made.
//! * vendored — the REAL `vendor --offline` wires the 5.4 / 6.0 / 9.0
//!   fixture locks; then, with the manifest and ledgers deleted:
//!   - the committed tarball attests `(vendored)`;
//!   - a tampered tarball member is omitted (`vendor_hash_mismatch`);
//!   - a record naming another package is omitted (`record_mismatch`);
//!   - `--offline` is omitted (`record_unavailable`);
//!   - with the ledger back but the wiring reverted, the leftover artifact
//!     is omitted (`vendor_unwired`), `--no-verify` included.
//! * hand-wired vendored — pnpm 1-6 locks (which `vendor` refuses) whose
//!   resolution a user pointed at a committed `.socket/vendor/` tarball.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha512};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::vex_e2e_common;
use vex_e2e_common::{
    assert_absent, assert_attested, assert_not_attested, binary, git_sha256, patch_view, run_vex,
    strip_ledgers, strip_manifest, Marker, PatchApi, VexRun,
};

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d";
/// uuid-shaped grant token BEFORE the patch uuid in the hosted URL: the
/// patch uuid is the LAST uuid segment.
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
const GHSA: &str = "GHSA-vex-lockfile-pnpm";
const VULNS: &[(&str, &[&str])] = &[(GHSA, &["CVE-2026-4242"])];
const ORIG: &[u8] = b"module.exports = function leftPad(s) { return s; };\n";
const PATCHED: &[u8] =
    b"/* SOCKET-PATCHED */\nmodule.exports = function leftPad(s) { return s; };\n";
const TAMPERED: &[u8] = b"/* NOT THE PATCH */\nmodule.exports = 0;\n";

/// Every captured pnpm release lock (majors 1-12) and its file name.
const HOSTED_ERAS: &[(&str, &str)] = &[
    ("1.43.1", "shrinkwrap.yaml"),
    ("2.25.7", "shrinkwrap.yaml"),
    ("3.8.1", "pnpm-lock.yaml"),
    ("4.14.4", "pnpm-lock.yaml"),
    ("5.18.11", "pnpm-lock.yaml"),
    ("6.35.1", "pnpm-lock.yaml"),
    ("7.33.7", "pnpm-lock.yaml"),
    ("8.15.9", "pnpm-lock.yaml"),
    ("9.15.9", "pnpm-lock.yaml"),
    ("10.33.0", "pnpm-lock.yaml"),
    ("11.27.0", "pnpm-lock.yaml"),
    ("12.4.2", "pnpm-lock.yaml"),
];

/// The captured locks `vendor` wires (lockfileVersion 5.4 / 6.0 / 9.0).
const VENDORED_ERAS: &[&str] = &["7.33.7", "8.15.9", "9.15.9", "10.33.0", "11.27.0", "12.4.2"];

/// The captured locks `vendor` refuses (shrinkwrap 3, lockfile 5.0-5.3).
const HAND_WIRED_ERAS: &[(&str, &str)] = &[
    ("1.43.1", "shrinkwrap.yaml"),
    ("2.25.7", "shrinkwrap.yaml"),
    ("3.8.1", "pnpm-lock.yaml"),
    ("4.14.4", "pnpm-lock.yaml"),
    ("5.18.11", "pnpm-lock.yaml"),
    ("6.35.1", "pnpm-lock.yaml"),
];

fn fixture_lock(version: &str, lock: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/pnpm-hosted")
        .join(version)
        .join(lock);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn hosted_url(host: &str) -> String {
    format!("{host}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz")
}

/// An npm tarball of left-pad whose `index.js` is `index`.
fn make_tgz(index: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (p, bytes) in [
        (
            "package/package.json",
            format!(r#"{{"name":"{DEP}","version":"{DEP_VERSION}"}}"#).into_bytes(),
        ),
        ("package/index.js", index.to_vec()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, p, bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

fn sri(bytes: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

/// The patch view the API serves: real before/after hashes of `index.js`,
/// so a pristine install reads `not_applied` and a foreign one
/// `hash_mismatch`.
fn view(uuid: &str, purl: &str) -> Value {
    let mut v = patch_view(
        uuid,
        purl,
        &[("package/index.js", &git_sha256(PATCHED))],
        VULNS,
    );
    v["files"]["package/index.js"]["beforeHash"] = Value::String(git_sha256(ORIG));
    v
}

fn api_with(uuid: &str, purl: &str) -> PatchApi {
    PatchApi::start(vec![(UUID.to_string(), view(uuid, purl))])
}

/// A stub project: package.json + `lock_name` + (when `index` is set) an
/// installed `node_modules/left-pad` the crawler finds.
fn write_project(root: &Path, lock_name: &str, lock: &str, index: Option<&[u8]>) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("package.json"),
        format!(
            "{{\n  \"name\": \"consumer\",\n  \"version\": \"0.0.0\",\n  \"private\": true,\n  \"dependencies\": {{\n    \"{DEP}\": \"{DEP_VERSION}\"\n  }}\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(root.join(lock_name), lock).unwrap();
    if let Some(index) = index {
        install(root, index);
    }
}

fn install(root: &Path, index: &[u8]) {
    let pkg = root.join("node_modules").join(DEP);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{DEP}", "version": "{DEP_VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), index).unwrap();
}

fn socket(root: &Path, args: &[&str]) -> (Option<i32>, Value, String) {
    let mut cmd = Command::new(binary());
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(k);
        }
    }
    let out = cmd
        .args(args)
        .arg("--cwd")
        .arg(root)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .current_dir(root)
        .output()
        .expect("spawn socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{args:?}: stdout not JSON ({e}):\n{stdout}\n{stderr}"));
    (out.status.code(), env, stderr)
}

/// The scan-time patch API (discovery + reference + view), on its own
/// runtime so the sync tests can drive it.
struct ScanApi {
    // Declared first: the server must drop while its runtime lives.
    server: MockServer,
    _rt: tokio::runtime::Runtime,
}

impl ScanApi {
    fn start(reference_url: &str, integrity: &str) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        rt.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "packages": [{ "purl": PURL, "patches": [{
                        "uuid": UUID, "purl": PURL, "tier": "free",
                        "cveIds": [], "ghsaIds": [], "severity": "high", "title": "t"
                    }]}],
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
                        "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
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
                    "results": { UUID: {
                        "status": "granted", "url": reference_url, "purl": PURL,
                        "artifacts": [{ "kind": "tarball", "url": reference_url,
                                        "integrity": { "sha512": integrity } }],
                        "registryOverride": null
                    }}
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(view(UUID, PURL)))
                .mount(&server)
                .await;
        });
        Self { server, _rt: rt }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }
}

/// `scan --mode hosted` over the fixture lock of pnpm `version`, with the
/// patched copy installed. Returns the project and the redirected lock.
fn hosted_project(tmp: &Path, version: &str, lock_name: &str) -> (PathBuf, String) {
    let root = tmp.join(format!("hosted-{version}"));
    write_project(
        &root,
        lock_name,
        &fixture_lock(version, lock_name),
        Some(PATCHED),
    );
    let url = hosted_url("https://patch.socket.dev");
    let pin = sri(&make_tgz(PATCHED));
    let scan_api = ScanApi::start(&url, &pin);
    let (code, env, stderr) = socket(
        &root,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--api-url",
            &scan_api.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    );
    drop(scan_api);
    assert_eq!(code, Some(0), "[{version}] scan: {env}\n{stderr}");
    assert_eq!(env["redirect"]["redirected"], 1, "[{version}] scan: {env}");
    let lock = std::fs::read_to_string(root.join(lock_name)).unwrap();
    assert!(
        lock.contains(&url) && lock.contains(&pin),
        "[{version}] the lock must pin the hosted tarball:\n{lock}"
    );
    assert!(!root.join(".socket/manifest.json").exists());
    strip_ledgers(&root);
    (root, lock)
}

fn set_index(root: &Path, index: &[u8]) {
    std::fs::write(root.join("node_modules").join(DEP).join("index.js"), index).unwrap();
}

#[test]
fn hosted_every_pnpm_era_manifestless_evidence_cells() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = binary();
    for (version, lock_name) in HOSTED_ERAS {
        let (root, lock) = hosted_project(tmp.path(), version, lock_name);

        // Installed + patched: the lockfile reference + the API record +
        // the hash-verified installed tree.
        let api = api_with(UUID, PURL);
        let out = run_vex(&bin, &root, &VexRun::online(&api));
        assert_eq!(out.code, Some(0), "[{version}] patched: {out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
        assert!(api.view_requests(UUID) >= 1, "[{version}]");

        // Installed evidence wins: a tampered or pristine copy is omitted,
        // `--no-verify` aside (it skips hashing, not the wiring gates).
        for (index, reason) in [(TAMPERED, "hash_mismatch"), (ORIG, "not_applied")] {
            set_index(&root, index);
            let out = run_vex(&bin, &root, &VexRun::online(&api));
            assert_eq!(out.code, Some(1), "[{version}] {reason}: {out}");
            assert_not_attested(&out.envelope, PURL, reason);
            assert_absent(out.doc.as_ref(), PURL);
        }

        // Not installed (a lockfile-only CI checkout): the lock's
        // integrity-pinned hosted wiring is the evidence.
        std::fs::remove_dir_all(root.join("node_modules")).unwrap();
        let out = run_vex(&bin, &root, &VexRun::online(&api));
        assert_eq!(out.code, Some(0), "[{version}] not installed: {out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
        install(&root, PATCHED);

        // The record must name the wired package AND patch.
        for (what, uuid, purl) in [
            ("another purl", UUID, "pkg:npm/right-pad@1.3.0"),
            ("another uuid", "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f", PURL),
        ] {
            let api = api_with(uuid, purl);
            let out = run_vex(&bin, &root, &VexRun::online(&api));
            assert_eq!(out.code, Some(1), "[{version}] record names {what}: {out}");
            assert_not_attested(&out.envelope, PURL, "record_mismatch");
            assert_absent(out.doc.as_ref(), PURL);
        }

        // Offline, nothing local: record_unavailable, zero network.
        let silent = PatchApi::empty();
        let out = run_vex(
            &bin,
            &root,
            &VexRun {
                proxy_url: Some(silent.uri()),
                ..VexRun::offline()
            },
        );
        assert_eq!(out.code, Some(1), "[{version}] offline: {out}");
        assert_not_attested(&out.envelope, PURL, "record_unavailable");
        silent.assert_no_requests();

        // Spoofed host: the same uuid-shaped path on a non-Socket origin is
        // not a patch reference — nothing is attested or fetched.
        let spoofed = lock.replace(
            "https://patch.socket.dev",
            "https://patch.socket.dev.evil.test",
        );
        assert_ne!(spoofed, lock);
        std::fs::write(root.join(lock_name), &spoofed).unwrap();
        let api = api_with(UUID, PURL);
        let out = run_vex(&bin, &root, &VexRun::online(&api));
        assert_eq!(out.code, Some(2), "[{version}] spoofed host: {out}");
        assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
        assert_absent(out.doc.as_ref(), PURL);
        api.assert_no_requests();
        eprintln!("hosted pnpm {version}: all cells OK");
    }
}

/// Stage a manifest + blob for `vendor --offline` over the stub install.
fn stage_patch(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut record = view(UUID, PURL);
    record.as_object_mut().unwrap().remove("purl");
    record["exportedAt"] = Value::String("2026-01-01T00:00:00Z".into());
    let manifest = serde_json::json!({ "patches": { PURL: record } });
    std::fs::write(socket.join("manifest.json"), manifest.to_string()).unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(PATCHED)), PATCHED).unwrap();
}

fn tarball_rel() -> String {
    format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz")
}

#[test]
fn vendored_every_wired_pnpm_era_manifestless_evidence_cells() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = binary();
    for version in VENDORED_ERAS {
        let root = tmp.path().join(format!("vendored-{version}"));
        let pristine_lock = fixture_lock(version, "pnpm-lock.yaml");
        write_project(&root, "pnpm-lock.yaml", &pristine_lock, Some(ORIG));
        let pristine_pkg = std::fs::read(root.join("package.json")).unwrap();
        stage_patch(&root);
        let (code, env, stderr) = socket(&root, &["vendor", "--json", "--offline"]);
        assert_eq!(code, Some(0), "[{version}] vendor: {env}\n{stderr}");
        assert_eq!(env["summary"]["applied"], 1, "[{version}] vendor: {env}");
        let tgz = root.join(tarball_rel());
        assert!(tgz.is_file(), "[{version}] no tarball");
        let wired_lock = std::fs::read(root.join("pnpm-lock.yaml")).unwrap();
        let wired_pkg = std::fs::read(root.join("package.json")).unwrap();
        let state = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();
        strip_manifest(&root);
        strip_ledgers(&root);
        // The committed artifact is the evidence, not node_modules.
        std::fs::remove_dir_all(root.join("node_modules")).unwrap();

        let api = api_with(UUID, PURL);
        let out = run_vex(&bin, &root, &VexRun::online(&api));
        assert_eq!(out.code, Some(0), "[{version}] vendored: {out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Vendored, VULNS);

        let bad = api_with(UUID, "pkg:npm/right-pad@1.3.0");
        let out = run_vex(&bin, &root, &VexRun::online(&bad));
        assert_eq!(out.code, Some(1), "[{version}] mismatch: {out}");
        assert_not_attested(&out.envelope, PURL, "record_mismatch");

        let out = run_vex(&bin, &root, &VexRun::offline());
        assert_eq!(out.code, Some(1), "[{version}] offline: {out}");
        assert_not_attested(&out.envelope, PURL, "record_unavailable");

        // A tampered member of the committed tarball.
        let good = std::fs::read(&tgz).unwrap();
        std::fs::write(&tgz, make_tgz(TAMPERED)).unwrap();
        let out = run_vex(&bin, &root, &VexRun::online(&api));
        assert_eq!(out.code, Some(1), "[{version}] tampered: {out}");
        assert_not_attested(&out.envelope, PURL, "vendor_hash_mismatch");
        assert_absent(out.doc.as_ref(), PURL);
        std::fs::write(&tgz, &good).unwrap();

        // Wiring reverted, ledger + artifact left behind: unwired.
        std::fs::write(root.join(".socket/vendor/state.json"), &state).unwrap();
        std::fs::write(root.join("pnpm-lock.yaml"), &pristine_lock).unwrap();
        std::fs::write(root.join("package.json"), &pristine_pkg).unwrap();
        let _ = std::fs::remove_file(root.join("pnpm-workspace.yaml"));
        for no_verify in [false, true] {
            let out = run_vex(
                &bin,
                &root,
                &VexRun {
                    no_verify,
                    ..VexRun::online(&api)
                },
            );
            assert_eq!(out.code, Some(1), "[{version}] unwired: {out}");
            assert_not_attested(&out.envelope, PURL, "vendor_unwired");
            assert_absent(out.doc.as_ref(), PURL);
        }
        assert_ne!(wired_lock, pristine_lock.as_bytes());
        assert_ne!(wired_pkg, pristine_pkg);
        eprintln!("vendored pnpm {version}: all cells OK");
    }
}

#[test]
fn hand_wired_legacy_pnpm_locks_attest_the_committed_tarball() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = binary();
    let tgz = make_tgz(PATCHED);
    let pin = sri(&tgz);
    let upstream = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==";
    for (version, lock_name) in HAND_WIRED_ERAS {
        let root = tmp.path().join(format!("hand-{version}"));
        let pristine = fixture_lock(version, lock_name);
        assert!(pristine.contains(upstream), "[{version}] fixture drift");
        // What a user hand-edit looks like: the resolution now also names
        // the committed tarball, pinned by its integrity (inline flow map
        // in lockfile 5.x, block map in shrinkwrap 3).
        let rel = tarball_rel();
        let wired = if pristine.contains("resolution: {integrity:") {
            pristine.replace(
                &format!("resolution: {{integrity: {upstream}}}"),
                &format!("resolution: {{integrity: {pin}, tarball: file:{rel}}}"),
            )
        } else {
            pristine.replace(
                &format!("integrity: {upstream}"),
                &format!("integrity: {pin}\n      tarball: file:{rel}"),
            )
        };
        assert_ne!(wired, pristine, "[{version}] the hand edit must land");
        write_project(&root, lock_name, &wired, None);
        let dir = root.join(format!(".socket/vendor/npm/{UUID}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(root.join(&rel), &tgz).unwrap();

        let api = api_with(UUID, PURL);
        let out = run_vex(&bin, &root, &VexRun::online(&api));
        assert_eq!(out.code, Some(0), "[{version}] hand-wired: {out}\n{wired}");
        assert_attested(out.doc(), PURL, UUID, Marker::Vendored, VULNS);

        // The same artifact with the lock back on the registry: nothing
        // references it (no ledger either), so there is nothing to attest —
        // exit 2 `manifest_not_found`, never a crash or another failure.
        std::fs::write(root.join(lock_name), &pristine).unwrap();
        let out = run_vex(&bin, &root, &VexRun::online(&api));
        assert_eq!(out.code, Some(2), "[{version}] unwired leftover: {out}");
        assert_eq!(
            out.envelope["error"]["code"], "manifest_not_found",
            "[{version}] unwired leftover: {out}"
        );
        assert!(out.doc.is_none(), "[{version}] unwired leftover: {out}");
        eprintln!("hand-wired pnpm {version}: OK");
    }
}
