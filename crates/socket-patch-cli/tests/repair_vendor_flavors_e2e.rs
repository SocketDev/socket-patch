//! End-to-end tests for `repair`'s vendored-artifact phase across the npm
//! FLAVORS — pnpm (lockfileVersion 9.0), yarn berry (4.x, node-modules
//! linker), bun (text bun.lock), and vlt's directory artifacts
//! (`repair_vendor_flavors_e2e/vlt.rs`). The npm-classic (`package-lock.json`)
//! flavor is covered by `repair_vendor_e2e.rs`; this file is the flavor
//! generalization of the same invariants:
//!
//!   (a) delete the vendored tarball  → `repair` rebuilds it byte-identically,
//!       the flavor's install wiring (lock rewrite) is left intact;
//!   (b) corrupt the vendored tarball → detected (ledger sha) and rebuilt;
//!   (c) tamper the ledger sha        → fail-closed, exit 1, artifact removed;
//!   (d) delete the ledger wholesale  → the lockfile's vendored-tarball
//!       reference (`scan_vendor_references` tokenizes the pnpm/yarn/bun
//!       locks) is reported as `vendor_ledger_missing`, never reconstructed.
//!
//! The fixtures run the ACTUAL `scan --vendor` flow in-test the way the
//! capstones stage it — a hand-written flavor lock (the pre-vendor shape each
//! backend's capstone asserts) plus an installed `node_modules/<dep>` copy,
//! driven through the built binary against a mock API (no real package
//! manager, no real registry). Flavor detection is text-based on the
//! lockfile, so vendoring proceeds offline from the installed copy + the
//! view-fetched patch content.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "vex_e2e_common/bun.rs"]
mod bun_vex;
#[path = "common/mod.rs"]
mod common;
#[path = "repair_vendor_flavors_e2e/vlt.rs"]
mod vlt;

const ORG_SLUG: &str = "test-org";
const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ENCODED: &str = "pkg%3Anpm%2Fleft-pad%401.3.0";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";
const AFTER_B64: &str = "YWZ0ZXIK";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// The three npm flavors this file parameterizes over. Each knows how to lay
/// down its pre-vendor lockfile and how to prove the vendor lock rewrite
/// survived a repair. The bun arm is further parameterized over the text
/// lock's `lockfileVersion` and the presence of a workspace member.
#[derive(Clone, Copy)]
enum Flavor {
    Pnpm,
    YarnBerry,
    Bun(BunLock),
}

/// One bun.lock shape: `lockfileVersion` 0 (bun 1.1.39–1.1.45 text opt-in),
/// 1 (bun 1.2/1.3) or 2 (bun 1.4), with or without a `workspace:` packages
/// entry. Workspace shapes matter because the vendor engine's workspace
/// gate refuses a FRESH vendor into a pre-v2 workspace lock, while `repair`
/// (and in-sync re-runs) on a lock that ALREADY carries the vendored tuple
/// must keep working — a project vendored before it grew a workspace member
/// must not be refused every maintenance verb.
#[derive(Clone, Copy)]
struct BunLock {
    version: u64,
    workspace: bool,
}

impl BunLock {
    /// The plain v1 shape the flavor-generic arms use.
    const V1: BunLock = BunLock {
        version: 1,
        workspace: false,
    };

    /// lockfileVersion {0, 1, 2} × {plain, workspace}.
    const MATRIX: [BunLock; 6] = [
        BunLock {
            version: 0,
            workspace: false,
        },
        BunLock {
            version: 0,
            workspace: true,
        },
        BunLock {
            version: 1,
            workspace: false,
        },
        BunLock {
            version: 1,
            workspace: true,
        },
        BunLock {
            version: 2,
            workspace: false,
        },
        BunLock {
            version: 2,
            workspace: true,
        },
    ];

    /// The `packages` entry bun writes for the `consumer` workspace member —
    /// the REAL per-version grammar (bun 1.1.45 vs 1.3.14/1.4.2 output): v0
    /// emits a 2-tuple carrying the member's deps object, v1/v2 the
    /// 1-tuple. Followed by bun's blank-line entry separator.
    fn workspace_entry(self) -> &'static str {
        if self.version == 0 {
            "    \"consumer\": [\"consumer@workspace:packages/consumer\", { \"dependencies\": { \"left-pad\": \"1.3.0\" } }],\n\n"
        } else {
            "    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n\n"
        }
    }

    /// Only a v2 lock accepts a FRESH vendor with the workspace entry
    /// present; the v0/v1 workspace shapes are reached the way real projects
    /// reach them — vendored first, workspace member added afterwards (bun
    /// keeps both the version and the vendored tuple on an in-place
    /// `bun install`; see [`BunLock::add_workspace_member`]).
    fn workspace_present_before_vendor(self) -> bool {
        self.workspace && self.version == 2
    }

    /// The pre-vendor lock text (real bun shape: no `configVersion` line on
    /// v0; the registry 4-tuple is grammar-identical across 0/1/2).
    fn lock_text(self, with_workspace: bool) -> String {
        format!(
            "{{\n  \"lockfileVersion\": {},\n  \"packages\": {{\n{}    \"{DEP}\": \
             [\"{DEP}@{DEP_VERSION}\", \"\", {{}}, \"sha512-orig==\"],\n  }}\n}}\n",
            self.version,
            if with_workspace {
                self.workspace_entry()
            } else {
                ""
            },
        )
    }

    /// Splice the workspace member into an already-vendored lock — what the
    /// post-vendor `bun install` leaves behind (vendored tuple byte-identical,
    /// version unchanged).
    fn add_workspace_member(self, root: &Path) {
        let path = root.join("bun.lock");
        let lock = std::fs::read_to_string(&path).unwrap();
        let spliced = lock.replacen(
            "  \"packages\": {\n",
            &format!("  \"packages\": {{\n{}", self.workspace_entry()),
            1,
        );
        assert_ne!(spliced, lock, "the workspace splice must hit");
        std::fs::write(&path, spliced).unwrap();
    }
}

impl Flavor {
    fn tag(self) -> String {
        match self {
            Flavor::Pnpm => "pnpm".to_string(),
            Flavor::YarnBerry => "yarn-berry".to_string(),
            Flavor::Bun(BunLock { version, workspace }) => format!(
                "bun(lockfileVersion {version}{})",
                if workspace { ", workspace" } else { "" }
            ),
        }
    }

    /// The committed lockfile the flavor's vendor backend rewrites.
    fn lock_name(self) -> &'static str {
        match self {
            Flavor::Pnpm => "pnpm-lock.yaml",
            Flavor::YarnBerry => "yarn.lock",
            Flavor::Bun(_) => "bun.lock",
        }
    }

    /// The `consumer` workspace member's manifest (bun refuses to install a
    /// lock that names a missing member; the engine is lock-only, this keeps
    /// the fixture honest).
    fn workspace_member(self) -> bool {
        matches!(
            self,
            Flavor::Bun(BunLock {
                workspace: true,
                ..
            })
        )
    }

    /// Write the pre-vendor lockfile (the shape each backend's capstone
    /// asserts as its `lock_before`). Extra files (`.yarnrc.yml` for berry)
    /// are laid down too.
    fn write_lock(self, root: &Path) {
        match self {
            Flavor::Pnpm => {
                std::fs::write(
                    root.join("pnpm-lock.yaml"),
                    format!(
                        "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      {DEP}:
        specifier: {DEP_VERSION}
        version: {DEP_VERSION}

packages:
  {DEP}@{DEP_VERSION}:
    resolution: {{integrity: sha512-orig==}}

snapshots:
  {DEP}@{DEP_VERSION}: {{}}
"
                    ),
                )
                .unwrap();
            }
            Flavor::YarnBerry => {
                std::fs::write(
                    root.join(".yarnrc.yml"),
                    "nodeLinker: node-modules\nenableGlobalCache: false\n",
                )
                .unwrap();
                std::fs::write(
                    root.join("yarn.lock"),
                    format!(
                        "# This file is generated by running \"yarn install\" inside your project.\n\
                         # Manual changes might be lost - proceed with caution!\n\n\
                         __metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                         \"{DEP}@npm:{DEP_VERSION}\":\n  version: {DEP_VERSION}\n  \
                         resolution: \"{DEP}@npm:{DEP_VERSION}\"\n  checksum: 10c0/{}\n  \
                         languageName: node\n  linkType: hard\n\n\
                         \"repair-flavors@workspace:.\":\n  version: 0.0.0-use.local\n  \
                         resolution: \"repair-flavors@workspace:.\"\n  dependencies:\n    \
                         {DEP}: \"npm:{DEP_VERSION}\"\n  languageName: unknown\n  linkType: soft\n",
                        "3".repeat(128)
                    ),
                )
                .unwrap();
            }
            Flavor::Bun(shape) => {
                std::fs::write(
                    root.join("bun.lock"),
                    shape.lock_text(shape.workspace_present_before_vendor()),
                )
                .unwrap();
            }
        }
    }

    /// Berry rewrites package.json (compact→pretty) on install and adds a
    /// `resolutions` entry on vendor; the root name is embedded in the lock.
    fn root_name(self) -> &'static str {
        match self {
            Flavor::YarnBerry => "repair-flavors",
            _ => "repair-flavors-test",
        }
    }

    /// After a successful repair, the lockfile must still carry the vendored
    /// tarball reference (install wiring intact). Returns a substring that
    /// must be present in the post-repair lock.
    fn wiring_marker(self) -> String {
        let tgz_rel = format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz");
        match self {
            // pnpm: `tarball: file:<rel>` on the rekeyed resolution.
            Flavor::Pnpm => format!("file:{tgz_rel}"),
            // berry: the `file:./<rel>` locator entry.
            Flavor::YarnBerry => format!("{DEP}@file:./{tgz_rel}"),
            // bun: the local-tarball 3-tuple element 0 `<name>@<bare-rel>`.
            Flavor::Bun(_) => format!("\"{DEP}@{tgz_rel}\""),
        }
    }
}

/// Vendorable flavor project: package.json + the flavor lockfile + the
/// installed package copy the vendor backend packs from.
fn write_fixture(root: &Path, flavor: Flavor) {
    let workspaces = if flavor.workspace_member() {
        r#","workspaces":["packages/*"]"#
    } else {
        ""
    };
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{"name":"{}","version":"0.0.0","private":true{workspaces},"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#,
            flavor.root_name()
        ),
    )
    .unwrap();
    if flavor.workspace_member() {
        let member = root.join("packages/consumer");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            member.join("package.json"),
            format!(
                r#"{{"name":"consumer","version":"1.0.0","dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
            ),
        )
        .unwrap();
    }
    flavor.write_lock(root);

    let pkg = root.join("node_modules").join(DEP);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{"name":"{DEP}","version":"{DEP_VERSION}"}}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// Discovery + view for `UUID`, with the after-blob content embedded so the
/// vendor/repair in-memory staging has the patch content (same shape as
/// repair_vendor_e2e.rs / scan_vendor_e2e.rs).
async fn mount_patch_api(mock: &MockServer) {
    mount_patch_api_with(mock, &[]).await;
}

/// [`mount_patch_api`] whose patch also carries `extra` files
/// (`(path, before, after)`).
async fn mount_patch_api_with(mock: &MockServer, extra: &[(&str, &[u8], &[u8])]) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
    let mut files = serde_json::json!({
        "package/index.js": {
            "beforeHash": before_hash,
            "afterHash":  after_hash,
            "blobContent": AFTER_B64,
        }
    });
    for (file, before, after) in extra {
        use base64::Engine as _;
        files[*file] = serde_json::json!({
            "beforeHash": git_sha256(before),
            "afterHash": git_sha256(after),
            "blobContent": base64::engine::general_purpose::STANDARD.encode(after),
        });
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": ["CVE-2026-0001"], "ghsaIds": [],
                    "severity": "high", "title": "vendor target"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Vendor patch", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": files,
            "vulnerabilities": {
                "GHSA-aaaa-bbbb-cccc": {
                    "cves": ["CVE-2026-0001"], "summary": "test vuln",
                    "severity": "high", "description": "details"
                }
            },
            "description": "Vendor patch", "license": "MIT", "tier": "free",
        })))
        .mount(mock)
        .await;
}


/// Runs through `common::run_with_env`, which seed-then-scrubs the ambient
/// `SOCKET_*` surface the binary binds via clap `env=` (SOCKET_DRY_RUN,
/// SOCKET_ECOSYSTEMS, SOCKET_CWD, ...) — an ambient value would silently
/// change what every test here exercises (SOCKET_DRY_RUN=true turns the
/// vendor setup and every repair into a no-op).
fn run_cli(root: &Path, mock_uri: &str, argv: &[&str]) -> (i32, String, String) {
    let mut full = argv.to_vec();
    full.extend_from_slice(&[
        "--json",
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ]);
    common::run_with_env(root, &full, &[("SOCKET_TELEMETRY_DISABLED", "1")])
}

/// `scan --vendor --yes` to establish a vendored flavor project; returns the
/// vendored tarball path (identical layout for every npm flavor). A v0/v1
/// bun workspace shape gains its workspace member AFTER vendoring — the only
/// way such a lock arises (a fresh vendor into it is refused by design).
fn vendor_project(root: &Path, mock_uri: &str, flavor: Flavor) -> PathBuf {
    let (code, stdout, stderr) = run_cli(root, mock_uri, &["scan", "--vendor", "--yes"]);
    assert_eq!(
        code,
        0,
        "{}: vendor setup failed: {stdout} {stderr}",
        flavor.tag()
    );
    let tgz = root.join(format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz"));
    assert!(
        tgz.is_file(),
        "{}: setup must vendor the tarball: {stdout}",
        flavor.tag()
    );
    if let Flavor::Bun(shape) = flavor {
        if shape.workspace && !shape.workspace_present_before_vendor() {
            shape.add_workspace_member(root);
        }
    }
    tgz
}

fn parse_env(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON ({e}): {stdout}"))
}

fn events_of(v: &serde_json::Value) -> Vec<serde_json::Value> {
    v["events"].as_array().cloned().unwrap_or_default()
}

/// Assert the flavor's install wiring survived: the post-repair lockfile still
/// references the vendored tarball.
fn assert_wiring_intact(root: &Path, flavor: Flavor) {
    let lock = std::fs::read_to_string(root.join(flavor.lock_name())).unwrap();
    let marker = flavor.wiring_marker();
    assert!(
        lock.contains(&marker),
        "{}: post-repair {} must still reference the vendored tarball ({marker}); got:\n{lock}",
        flavor.tag(),
        flavor.lock_name(),
    );
}

// ── (a) deleted tarball → rebuilt byte-identically, wiring intact ──────────

async fn deleted_tarball_rebuilds(flavor: Flavor) {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), flavor);
    let tgz = vendor_project(tmp.path(), &mock.uri(), flavor);
    let tgz_bytes = std::fs::read(&tgz).unwrap();
    let lock1 = std::fs::read(tmp.path().join(flavor.lock_name())).unwrap();

    std::fs::remove_file(&tgz).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "{}: stdout={stdout} stderr={stderr}", flavor.tag());
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "{}: envelope={v}", flavor.tag());
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "{}: envelope={v}",
        flavor.tag()
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "{}: deterministic rebuild must reproduce the recorded bytes",
        flavor.tag()
    );
    assert_eq!(
        std::fs::read(tmp.path().join(flavor.lock_name())).unwrap(),
        lock1,
        "{}: lockfile untouched by repair",
        flavor.tag()
    );
    assert_wiring_intact(tmp.path(), flavor);
}

#[tokio::test]
async fn repair_rebuilds_deleted_pnpm_tarball() {
    deleted_tarball_rebuilds(Flavor::Pnpm).await;
}

#[tokio::test]
async fn repair_rebuilds_deleted_yarn_berry_tarball() {
    deleted_tarball_rebuilds(Flavor::YarnBerry).await;
}

/// Every bun.lock shape — lockfileVersion {0, 1, 2} × {plain, workspace}.
/// `repair` rebuilds through the vendor engine, whose workspace gate must
/// let an already-vendored (`Ours`) instance through on a pre-v2 workspace
/// lock instead of refusing and leaving the lock pointing at a tarball
/// nobody rebuilt (cold `bun install --frozen-lockfile` then ENOENTs).
#[tokio::test]
async fn repair_rebuilds_deleted_bun_tarball() {
    for shape in BunLock::MATRIX {
        deleted_tarball_rebuilds(Flavor::Bun(shape)).await;
    }
}

/// Manifest-less VEX over every REPAIRED bun shape (lockfileVersion
/// {0, 1, 2} × {plain, workspace}): the rebuilt committed artifact is the
/// vendored evidence, so a lockfile-only checkout with the manifest deleted
/// is attested `(vendored)` from the ledger and — ledgers deleted — from
/// the lock + patch API; offline → `record_unavailable`; the pristine lock
/// back → NOT attested ([`bun_vex::run_bun_vex_matrix`]).
#[tokio::test]
async fn repaired_bun_tarball_attests_without_a_manifest() {
    for shape in BunLock::MATRIX {
        let flavor = Flavor::Bun(shape);
        let mock = MockServer::start().await;
        mount_patch_api(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path(), flavor);
        let pristine = std::fs::read(tmp.path().join(flavor.lock_name())).unwrap();
        let tgz = vendor_project(tmp.path(), &mock.uri(), flavor);
        std::fs::remove_file(&tgz).unwrap();
        let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
        assert_eq!(code, 0, "{}: stdout={stdout} stderr={stderr}", flavor.tag());
        let scratch = tempfile::tempdir().unwrap();
        let tag = flavor.tag();
        let case = bun_vex::BunVexCase {
            tag: &tag,
            mode: bun_vex::BunMode::Vendored,
            purl: PURL,
            uuid: UUID,
            files: vec![("package/index.js".to_string(), common::git_sha256(AFTER))],
            vulns: &[("GHSA-aaaa-bbbb-cccc", &["CVE-2026-0001"])],
            lock: flavor.lock_name(),
            registry_lock: pristine,
            patch_server_url: None,
        };
        bun_vex::run_bun_vex_matrix(tmp.path(), scratch.path(), &case, |_| {});
    }
}

// ── (b) corrupt tarball → detected + rebuilt ───────────────────────────────

async fn corrupt_tarball_rebuilds(flavor: Flavor) {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), flavor);
    let tgz = vendor_project(tmp.path(), &mock.uri(), flavor);
    let tgz_bytes = std::fs::read(&tgz).unwrap();

    std::fs::write(&tgz, b"\x1f\x8bgarbage").unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "{}: stdout={stdout} stderr={stderr}", flavor.tag());
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "{}: envelope={v}", flavor.tag());
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "{}: rebuild restores the recorded bytes",
        flavor.tag()
    );
    assert_wiring_intact(tmp.path(), flavor);
}

#[tokio::test]
async fn repair_rebuilds_corrupt_pnpm_tarball() {
    corrupt_tarball_rebuilds(Flavor::Pnpm).await;
}

#[tokio::test]
async fn repair_rebuilds_corrupt_yarn_berry_tarball() {
    corrupt_tarball_rebuilds(Flavor::YarnBerry).await;
}

#[tokio::test]
async fn repair_rebuilds_corrupt_bun_tarball() {
    for shape in BunLock::MATRIX {
        corrupt_tarball_rebuilds(Flavor::Bun(shape)).await;
    }
}

/// An entry stamped with a flavor this release has no backend for (written
/// by a newer socket-patch, e.g. `future-pm`) is never judged or rebuilt: repair
/// warns `vendor_wiring_unknown_revert_blocked` and leaves the ledger, the
/// lock and the (here deleted) artifact exactly as found.
#[tokio::test]
async fn repair_skips_an_entry_with_an_unknown_flavor() {
    let flavor = Flavor::Pnpm;
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), flavor);
    let tgz = vendor_project(tmp.path(), &mock.uri(), flavor);
    std::fs::remove_file(&tgz).unwrap();

    let state_path = tmp.path().join(".socket/vendor/state.json");
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    v["entries"][PURL]["flavor"] = serde_json::json!("future-pm");
    std::fs::write(&state_path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let state_before = std::fs::read(&state_path).unwrap();
    let lock_before = std::fs::read(tmp.path().join(flavor.lock_name())).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let env = parse_env(&stdout);
    assert!(
        !events_of(&env).iter().any(|e| e["action"] == "rebuilt"),
        "{env}"
    );
    assert!(
        events_of(&env).iter().any(|e| e["action"] == "skipped"
            && e["purl"] == PURL
            && e["errorCode"] == "vendor_wiring_unknown_revert_blocked"),
        "{env}"
    );
    assert!(
        !tgz.exists(),
        "an unknown-flavor artifact must not be rebuilt"
    );
    assert_eq!(std::fs::read(&state_path).unwrap(), state_before);
    assert_eq!(
        std::fs::read(tmp.path().join(flavor.lock_name())).unwrap(),
        lock_before
    );
}

// ── (c) tampered ledger sha → fail-closed ──────────────────────────────────

async fn tampered_ledger_fails_closed(flavor: Flavor) {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), flavor);
    let tgz = vendor_project(tmp.path(), &mock.uri(), flavor);

    let state_path = tmp.path().join(".socket/vendor/state.json");
    let state = std::fs::read_to_string(&state_path).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&state).unwrap();
    v["entries"][PURL]["artifact"]["sha256"] = serde_json::json!("0".repeat(64));
    std::fs::write(&state_path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "{}: stdout={stdout} stderr={stderr}", flavor.tag());
    let env = parse_env(&stdout);
    assert!(
        events_of(&env)
            .iter()
            .any(|e| e["action"] == "failed" && e["errorCode"] == "vendor_artifact_rebuild_failed"),
        "{}: envelope={env}",
        flavor.tag()
    );
    assert!(
        !tgz.exists(),
        "{}: an unverifiable rebuild must not be left on disk",
        flavor.tag()
    );
}

#[tokio::test]
async fn repair_fails_closed_on_tampered_pnpm_ledger_sha() {
    tampered_ledger_fails_closed(Flavor::Pnpm).await;
}

#[tokio::test]
async fn repair_fails_closed_on_tampered_yarn_berry_ledger_sha() {
    tampered_ledger_fails_closed(Flavor::YarnBerry).await;
}

#[tokio::test]
async fn repair_fails_closed_on_tampered_bun_ledger_sha() {
    tampered_ledger_fails_closed(Flavor::Bun(BunLock::V1)).await;
}

// ── (d) ledger deleted wholesale → reported, never reconstructed ──────────

async fn ledger_gone_is_reported(flavor: Flavor) {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), flavor);
    let tgz = vendor_project(tmp.path(), &mock.uri(), flavor);
    let lock1 = std::fs::read(tmp.path().join(flavor.lock_name())).unwrap();

    // The whole .socket/vendor tree (state.json included) is gone — only the
    // rewired lockfile pins the vendored tarball. `scan_vendor_references`
    // must tokenize the flavor lock and recover the (npm, uuid, relpath)
    // reference, which repair reports instead of re-synthesizing a ledger.
    std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "{}: stdout={stdout} stderr={stderr}", flavor.tag());
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["errorCode"] == "vendor_ledger_missing"
            && e["uuid"] == UUID),
        "{}: envelope={v}",
        flavor.tag()
    );
    assert!(!tgz.exists(), "{}: nothing rebuilt", flavor.tag());
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "{}: no ledger synthesized",
        flavor.tag()
    );
    assert_eq!(
        std::fs::read(tmp.path().join(flavor.lock_name())).unwrap(),
        lock1,
        "{}: lockfile untouched",
        flavor.tag()
    );
}

#[tokio::test]
async fn repair_reports_missing_pnpm_ledger() {
    ledger_gone_is_reported(Flavor::Pnpm).await;
}

#[tokio::test]
async fn repair_reports_missing_yarn_berry_ledger() {
    ledger_gone_is_reported(Flavor::YarnBerry).await;
}

#[tokio::test]
async fn repair_reports_missing_bun_ledger() {
    ledger_gone_is_reported(Flavor::Bun(BunLock::V1)).await;
}
