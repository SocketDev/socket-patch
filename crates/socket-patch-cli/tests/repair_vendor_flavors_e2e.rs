//! End-to-end tests for `repair`'s vendored-artifact phase across the npm
//! FLAVORS — pnpm (lockfileVersion 9.0), yarn berry (4.x, node-modules
//! linker), and bun (text bun.lock). The npm-classic (`package-lock.json`)
//! flavor is covered by `repair_vendor_e2e.rs`; this file is the flavor
//! generalization of the same invariants:
//!
//!   (a) delete the vendored tarball  → `repair` rebuilds it byte-identically,
//!       the flavor's install wiring (lock rewrite) is left intact;
//!   (b) corrupt the vendored tarball → detected (ledger sha) and rebuilt;
//!   (c) tamper the ledger sha        → fail-closed, exit 1, artifact removed;
//!   (d) delete the ledger wholesale  → RECONSTRUCTED from the lockfile's
//!       vendored-tarball reference (`scan_vendor_references` tokenizes the
//!       pnpm/yarn/bun locks) and the artifact rebuilt.
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
/// used to be refused every maintenance verb, with `repair` leaving the lock
/// pointing at a tarball it declined to rebuild.
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
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
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
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": AFTER_B64,
                }
            },
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

/// Serve the after-blob for `--download-mode file` repairs (the ledger-gone
/// reconstruction path runs before the vendored entry is re-synthesized, so
/// its patch content is fetched via the blob endpoint).
async fn mount_blob(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{}",
            git_sha256(AFTER)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(AFTER))
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
/// by a newer socket-patch, e.g. `vlt`) is never judged or rebuilt: repair
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
    v["entries"][PURL]["flavor"] = serde_json::json!("vlt");
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

// ── (d) ledger deleted wholesale → reconstruct from lockfile references ─────

async fn ledger_gone_reconstructs_from_lock(flavor: Flavor) {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), flavor);
    let tgz = vendor_project(tmp.path(), &mock.uri(), flavor);
    let lock1 = std::fs::read(tmp.path().join(flavor.lock_name())).unwrap();

    // The whole .socket/vendor tree (state.json included) is gone — only the
    // rewired lockfile pins the vendored tarball. `scan_vendor_references`
    // must tokenize the flavor lock and recover the (npm, uuid, relpath)
    // reference to reconstruct the entry and rebuild the artifact.
    std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();

    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    assert_eq!(code, 0, "{}: stdout={stdout} stderr={stderr}", flavor.tag());
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "{}: envelope={v}", flavor.tag());
    assert!(tgz.is_file(), "{}: artifact rebuilt", flavor.tag());
    assert_eq!(
        std::fs::read(tmp.path().join(flavor.lock_name())).unwrap(),
        lock1,
        "{}: lockfile untouched by reconstruction",
        flavor.tag()
    );

    // The re-synthesized ledger entry names the uuid recovered from the
    // lockfile path and fingerprints the rebuilt bytes.
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    let entry = &state["entries"][PURL];
    assert_eq!(entry["uuid"], UUID, "{}: state={state}", flavor.tag());
    assert_eq!(
        entry["artifact"]["sha256"],
        hex::encode(Sha256::digest(std::fs::read(&tgz).unwrap())),
        "{}: recomputed fingerprint matches the rebuilt artifact: {state}",
        flavor.tag()
    );
    assert_wiring_intact(tmp.path(), flavor);
}

// ── (e) ledger gone + drifted installed copy → fail-closed ─────────────────
//
// The reconstructed entry records no sha; the rewired lockfile's integrity
// (pnpm `integrity:`, berry `checksum: 10c0/…`, bun tuple sha512) is the ONLY
// anchor for the rebuilt bytes. A rebuild packed from an installed copy that
// drifted since vendoring (a file added by a build tool, an edited unpatched
// file) can never match that integrity — the package manager rejects the
// artifact on its next install. Repair must fail closed, not report success
// and bless the drifted bytes into a fresh ledger (which would make every
// later repair see Healthy and never fix it).

async fn ledger_gone_drifted_copy_fails_closed(flavor: Flavor) {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), flavor);
    let tgz = vendor_project(tmp.path(), &mock.uri(), flavor);
    let lock1 = std::fs::read(tmp.path().join(flavor.lock_name())).unwrap();

    // Drift an UNPATCHED part of the installed copy (patched-file tampering
    // is already caught by the beforeHash gate; this is invisible to it).
    std::fs::write(
        tmp.path().join("node_modules").join(DEP).join("drifted.js"),
        b"injected after vendoring\n",
    )
    .unwrap();
    std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();

    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    assert_eq!(
        code,
        1,
        "{}: a rebuild that cannot match the lockfile's recorded integrity must fail closed: \
         stdout={stdout} stderr={stderr}",
        flavor.tag()
    );
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "failed" && e["errorCode"] == "vendor_artifact_rebuild_failed"),
        "{}: envelope={v}",
        flavor.tag()
    );
    assert!(
        !tgz.exists(),
        "{}: an artifact the lockfile rejects must not be left on disk",
        flavor.tag()
    );
    assert_eq!(
        std::fs::read(tmp.path().join(flavor.lock_name())).unwrap(),
        lock1,
        "{}: the lockfile (the trust anchor) stays untouched",
        flavor.tag()
    );
}

#[tokio::test]
async fn repair_fails_closed_on_drifted_copy_pnpm() {
    ledger_gone_drifted_copy_fails_closed(Flavor::Pnpm).await;
}

#[tokio::test]
async fn repair_fails_closed_on_drifted_copy_yarn_berry() {
    ledger_gone_drifted_copy_fails_closed(Flavor::YarnBerry).await;
}

#[tokio::test]
async fn repair_fails_closed_on_drifted_copy_bun() {
    ledger_gone_drifted_copy_fails_closed(Flavor::Bun(BunLock::V1)).await;
}

#[tokio::test]
async fn repair_reconstructs_pnpm_ledger_from_lockfile() {
    ledger_gone_reconstructs_from_lock(Flavor::Pnpm).await;
}

// ── (f) reconstructed empty-wiring entry: revert must not brick installs ────
//
// Empirically confirmed brick (real pnpm@10.34.5 project, 2026-08-18): after
// `repair` reconstructs a ledger-gone vendored entry from the lockfile, the
// entry carries EMPTY wiring (npm-family pre-vendor lock fragments are not
// offline-recoverable). A subsequent `vendor --revert` used to exit 0 with a
// bare {"action":"removed"} event — zero warnings — while DELETING the
// vendored tarball pnpm-lock.yaml still resolves through in several places;
// every later `pnpm install` then fails ENOENT on the missing file: tarball.
// The npm-family backends now fail closed
// (`vendor_wiring_unknown_revert_blocked`) when there is nothing to replay
// and the lock still references the artifact, and still remove genuinely
// orphaned artifacts once the lock no longer does. `repair`'s reconstruction
// also stamps the flavor it found the reference in (asserted below), so the
// revert routes to the backend whose guard probes the RIGHT lockfile; a
// flavor-None entry falls back to the package-lock backend, which is
// guarded too (repair_vendor_e2e.rs test 12).

#[tokio::test]
async fn revert_of_reconstructed_pnpm_entry_fails_closed_then_recovers() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), Flavor::Pnpm);
    let lock_pre = std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap();
    let pkg_pre = std::fs::read(tmp.path().join("package.json")).unwrap();
    let tgz = vendor_project(tmp.path(), &mock.uri(), Flavor::Pnpm);
    let lock_vendored = std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap();

    // Ledger gone; artifact + rewired lock intact (the empirical shape).
    // The anchored reconstruction restores the entry with wiring: [].
    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "reconstruction: stdout={stdout} stderr={stderr}");
    let state_path = tmp.path().join(".socket/vendor/state.json");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(
        state["entries"][PURL]["wiring"].as_array().map(Vec::len),
        Some(0),
        "npm wiring is not offline-recoverable: {state}"
    );
    // The reconstruction found the reference in pnpm-lock.yaml (v9), so the
    // entry is stamped with the pnpm flavor — revert routes to the pnpm
    // backend and its guard probes pnpm-lock.yaml, not package-lock.json.
    assert_eq!(
        state["entries"][PURL]["flavor"],
        serde_json::json!("pnpm"),
        "reconstruction stamps the detected flavor: {state}"
    );

    // Nothing to replay + the lock still resolves through the artifact:
    // revert must refuse loudly instead of silently removing the tarball.
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_ne!(
        code, 0,
        "revert of an empty-wiring entry the lock still references must fail closed: \
         stdout={stdout} stderr={stderr}"
    );
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["errorCode"] == "vendor_wiring_unknown_revert_blocked"),
        "envelope={v}"
    );
    assert!(
        tgz.is_file(),
        "the artifact the lock still references must survive the refusal"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        lock_vendored,
        "the lock stays untouched by the refusal"
    );

    // Recovery, exactly as the refusal advises: `repair` keeps the vendored
    // artifact healthy (idempotent — the entry and tarball survive)...
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(
        code, 0,
        "repair after refusal: stdout={stdout} stderr={stderr}"
    );
    assert!(tgz.is_file(), "repair keeps the artifact");

    // ...and once the pre-vendor surfaces are restored (the manual-restore
    // arm — the wiring originals are unrecoverable by design), a normal
    // revert removes the now-orphaned artifact cleanly.
    std::fs::write(tmp.path().join("pnpm-lock.yaml"), &lock_pre).unwrap();
    std::fs::write(tmp.path().join("package.json"), &pkg_pre).unwrap();
    let ws = tmp.path().join("pnpm-workspace.yaml");
    if ws.exists() {
        std::fs::remove_file(&ws).unwrap();
    }
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_eq!(code, 0, "final revert: stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "removed" && e["purl"] == PURL),
        "envelope={v}"
    );
    assert!(
        !tmp.path()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists(),
        "the orphaned artifact dir is removed"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        lock_pre,
        "clean end state: the restored pre-vendor lock is untouched"
    );
    // The ledger entry is gone — either the state file was removed with its
    // last entry, or it persists with an empty entries map.
    match std::fs::read_to_string(&state_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Ok(text) => {
            let state: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                state["entries"].as_object().map(serde_json::Map::len),
                Some(0),
                "ledger entry gone: {state}"
            );
        }
        Err(e) => panic!("unreadable state.json: {e}"),
    }
}

#[tokio::test]
async fn repair_reconstructs_yarn_berry_ledger_from_lockfile() {
    ledger_gone_reconstructs_from_lock(Flavor::YarnBerry).await;
}

#[tokio::test]
async fn repair_reconstructs_bun_ledger_from_lockfile() {
    ledger_gone_reconstructs_from_lock(Flavor::Bun(BunLock::V1)).await;
}
