//! Hermetic manifest-less VEX cells for vlt — every `vlt-lock.json` grammar
//! era, no vlt binary, all three OSes, never `#[ignore]`d.
//!
//! The real-vlt halves live in `e2e_redirect_vlt_build.rs` (hosted) and
//! `e2e_vendor_vlt_build.rs` (vendored), which end in
//! [`run_vlt_vex_matrix`]. This suite covers the evidence edges a real
//! install cannot stage, over the eras the hosted rewriter writes
//! (`lockfileVersion: 1` tilde ids, `0` legacy `·npm·` ids, and the
//! version-less `··` ids):
//!
//! * hosted — the REAL `scan --mode hosted` (a wiremock patch API that also
//!   serves the artifact the vlt preflight fetches, so the hosted URL is on
//!   the mock origin and `vex` gets it as `--patch-server-url`) rewrites the
//!   lock over an importer copy; then vlt's installed state is staged (the
//!   importer copy and `node_modules/.vlt/<DepID>/node_modules/left-pad`)
//!   and, with the manifest deleted:
//!   - the redirect ledger's embedded record attests offline;
//!   - with the ledgers deleted too, installed + patched attests
//!     `(redirected)` from the patch API's record;
//!   - a tampered or pristine store copy is omitted (`hash_mismatch` /
//!     `not_applied`) even though the importer copy is patched;
//!   - not installed attests from the lock's sha512 pin;
//!   - a record naming another package, or another patch, is omitted
//!     (`record_mismatch`);
//!   - `--offline` is omitted (`record_unavailable`) with zero requests;
//!   - the same URL off the configured origin, on a look-alike host, or with
//!     an uppercase patch uuid is not a reference to that patch;
//!   - a BOM-prefixed lock (vlt cannot read it) references nothing.
//! * a same-`name@version` instance a named alias still resolves from its
//!   registry keeps the hosted ref off the lockfile basis: only an installed
//!   tree whose every copy verifies attests.
//!
//! The vendored cells (committed dir artifact, tampered, mismatch, offline,
//! unwired) run `vendor --offline` and live with the vendored CLI.

use std::path::{Path, PathBuf};

use wiremock::MockServer;

#[path = "../vlt_hosted_common/mod.rs"]
mod hosted;
#[path = "../vex_e2e_common/vlt.rs"]
mod vlt_vex;

use hosted::{Era, NAME, PATCHED, PRISTINE, PURL, UUID, VERSION};
use vlt_vex::{
    assert_absent, assert_attested, assert_not_attested, binary, git_sha256, patch_view, run_vex,
    run_vlt_vex_matrix, strip_ledgers, Marker, PatchApi, VexRun, VltMode, VltVexCase, VLT_LOCK,
};

const VULNS: &[(&str, &[&str])] = &[(hosted::GHSA, &["CVE-2026-4242"])];
const TAMPERED: &[u8] = b"module.exports = 'not the patch'\n";
const ERAS: &[(Era, &str)] = &[(Era::V1, "v1"), (Era::V0, "v0"), (Era::A0, "a0")];

/// The view the API serves: real before/after hashes of `index.js`, so a
/// pristine install reads `not_applied` and a foreign one `hash_mismatch`.
fn view(uuid: &str, purl: &str) -> serde_json::Value {
    let mut v = patch_view(
        uuid,
        purl,
        &[("package/index.js", &git_sha256(PATCHED))],
        VULNS,
    );
    v["files"]["package/index.js"]["beforeHash"] = serde_json::Value::String(git_sha256(PRISTINE));
    v
}

fn api_with(uuid: &str, purl: &str) -> PatchApi {
    PatchApi::start(vec![(UUID.to_string(), view(uuid, purl))])
}

/// vlt's installed state for `id`: the importer copy and its store entry,
/// both holding `index`.
fn install(root: &Path, id: &str, index: &[u8]) {
    let _ = std::fs::remove_dir_all(root.join("node_modules"));
    hosted::install_importer(root, index);
    hosted::install_store(root, id, index);
}

struct HostedProject {
    root: PathBuf,
    /// The mock origin the lock's hosted URL is on.
    origin: String,
    /// The lock `scan --mode hosted` wrote.
    lock: String,
    /// The lock before the scan.
    registry_lock: String,
}

/// `scan --mode hosted` over a registry lock of `era` with a pristine
/// importer copy (nothing in vlt's store, so the heal has nothing to do).
fn hosted_project(tmp: &Path, era: Era, tag: &str) -> HostedProject {
    let root = tmp.join(format!("hosted-{tag}"));
    std::fs::create_dir_all(&root).unwrap();
    hosted::write_vlt_project(&root, era);
    let registry_lock = hosted::read(&root, VLT_LOCK);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());
    rt.block_on(hosted::mock_all(&server));
    let (code, doc) = hosted::scan_hosted(&root, &server, &[], &[]);
    assert_eq!(code, 0, "[{tag}] scan: {doc:#}");
    assert_eq!(hosted::redirected(&doc), 1, "[{tag}] scan: {doc:#}");
    let lock = hosted::read(&root, VLT_LOCK);
    let url = hosted::artifact_url(&server);
    let pin = hosted::sha512_sri(&hosted::patched_tarball());
    assert!(
        lock.contains(&url) && lock.contains(&pin),
        "[{tag}] the lock must pin the hosted tarball:\n{lock}"
    );
    assert!(!root.join(".socket/manifest.json").exists());
    assert!(hosted::ledger_path(&root).is_file(), "[{tag}]");
    HostedProject {
        root,
        origin: server.uri(),
        lock,
        registry_lock,
    }
}

#[test]
fn hosted_every_vlt_era_manifestless_evidence_cells() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = binary();
    for (era, tag) in ERAS {
        let p = hosted_project(tmp.path(), *era, tag);
        let root = &p.root;
        let id = era.dep_id();
        let online = |api: &PatchApi| VexRun {
            patch_server_url: Some(p.origin.clone()),
            ..VexRun::online(api)
        };
        install(root, id, PATCHED);

        let silent = PatchApi::empty();
        let out = run_vex(
            &bin,
            root,
            &VexRun {
                patch_server_url: Some(p.origin.clone()),
                proxy_url: Some(silent.uri()),
                ..VexRun::offline()
            },
        );
        assert_eq!(out.code, Some(0), "[{tag}] ledger, offline: {out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
        silent.assert_no_requests();
        strip_ledgers(root);

        let api = api_with(UUID, PURL);
        let out = run_vex(&bin, root, &online(&api));
        assert_eq!(out.code, Some(0), "[{tag}] patched: {out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
        assert!(api.view_requests(UUID) >= 1, "[{tag}]");

        for (index, reason) in [(TAMPERED, "hash_mismatch"), (PRISTINE, "not_applied")] {
            hosted::install_store(root, id, index);
            let out = run_vex(&bin, root, &online(&api));
            assert_eq!(out.code, Some(1), "[{tag}] store {reason}: {out}");
            assert_not_attested(&out.envelope, PURL, reason);
            assert_absent(out.doc.as_ref(), PURL);
        }

        std::fs::remove_dir_all(root.join("node_modules")).unwrap();
        let out = run_vex(&bin, root, &online(&api));
        assert_eq!(out.code, Some(0), "[{tag}] not installed: {out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
        install(root, id, PATCHED);

        for (what, uuid, purl) in [
            ("another purl", UUID, "pkg:npm/right-pad@1.3.0"),
            ("another uuid", "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f", PURL),
        ] {
            let api = api_with(uuid, purl);
            let out = run_vex(&bin, root, &online(&api));
            assert_eq!(out.code, Some(1), "[{tag}] record names {what}: {out}");
            assert_not_attested(&out.envelope, PURL, "record_mismatch");
            assert_absent(out.doc.as_ref(), PURL);
        }

        let silent = PatchApi::empty();
        let out = run_vex(
            &bin,
            root,
            &VexRun {
                patch_server_url: Some(p.origin.clone()),
                proxy_url: Some(silent.uri()),
                ..VexRun::offline()
            },
        );
        assert_eq!(out.code, Some(1), "[{tag}] offline: {out}");
        assert_not_attested(&out.envelope, PURL, "record_unavailable");
        silent.assert_no_requests();

        let api = api_with(UUID, PURL);
        let out = run_vex(&bin, root, &VexRun::online(&api));
        assert_eq!(out.code, Some(2), "[{tag}] origin not configured: {out}");
        assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
        api.assert_no_requests();

        let (host, port) = p
            .origin
            .trim_start_matches("http://")
            .rsplit_once(':')
            .unwrap();
        for (what, lock) in [
            (
                "look-alike host",
                p.lock
                    .replace(&p.origin, &format!("http://{host}.evil.test:{port}")),
            ),
            (
                "uppercase patch uuid",
                p.lock.replace(UUID, &UUID.to_ascii_uppercase()),
            ),
        ] {
            assert_ne!(lock, p.lock, "[{tag}] {what}");
            std::fs::write(root.join(VLT_LOCK), &lock).unwrap();
            let api = api_with(UUID, PURL);
            let out = run_vex(&bin, root, &online(&api));
            assert_ne!(out.code, Some(0), "[{tag}] {what}: {out}");
            assert_absent(out.doc.as_ref(), PURL);
            assert_eq!(api.view_requests(UUID), 0, "[{tag}] {what}");
        }

        std::fs::write(root.join(VLT_LOCK), format!("\u{feff}{}", p.lock)).unwrap();
        let api = api_with(UUID, PURL);
        let out = run_vex(&bin, root, &online(&api));
        assert_eq!(out.code, Some(2), "[{tag}] BOM lock: {out}");
        assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
        api.assert_no_requests();
        std::fs::write(root.join(VLT_LOCK), &p.lock).unwrap();
        assert_ne!(p.lock, p.registry_lock);
        eprintln!("hosted vlt {tag}: all cells OK");
    }
}

#[test]
fn hosted_vlt_checkout_runs_the_shared_manifestless_matrix() {
    let tmp = tempfile::tempdir().unwrap();
    let p = hosted_project(tmp.path(), Era::V1, "matrix");
    let case = VltVexCase {
        tag: "hermetic-v1",
        mode: VltMode::Hosted,
        purl: PURL,
        uuid: UUID,
        files: vec![("package/index.js".to_string(), git_sha256(PATCHED))],
        vulns: VULNS,
        registry_lock: p.registry_lock.clone().into_bytes(),
        patch_server_url: Some(p.origin.clone()),
    };
    run_vlt_vex_matrix(&p.root, tmp.path(), &case, |checkout| {
        assert!(!checkout.join("node_modules").exists());
        install(checkout, Era::V1.dep_id(), PATCHED);
    });
}

#[test]
fn a_same_version_alias_registry_instance_needs_every_copy_to_verify() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let url = format!(
        "https://patch.socket.dev/patch/npm/{NAME}/{VERSION}/{}/{UUID}/{NAME}-{VERSION}.tgz",
        hosted::TOKEN
    );
    let pin = hosted::sha512_sri(&hosted::patched_tarball());
    let foreign = "~acme~left-pad@1.3.0";
    let lock = hosted::vlt_lock(
        Era::V1,
        &[
            hosted::node(foreign, hosted::UPSTREAM_SHA512, hosted::REGISTRY_URL),
            hosted::node(Era::V1.dep_id(), &pin, &url),
        ],
    )
    .replace(
        "\"options\": {}",
        "\"options\": {\"registries\": {\"acme\": \"https://npm.acme.example/\"}}",
    );
    hosted::write_package_json(root);
    std::fs::write(root.join(VLT_LOCK), lock).unwrap();
    let api = api_with(UUID, PURL);

    let out = run_vex(&binary(), root, &VexRun::online(&api));
    assert_eq!(out.code, Some(1), "not installed: {out}");
    assert_not_attested(&out.envelope, PURL, "package_not_found");

    install(root, Era::V1.dep_id(), PATCHED);
    hosted::install_store(root, foreign, PRISTINE);
    let out = run_vex(&binary(), root, &VexRun::online(&api));
    assert_eq!(out.code, Some(1), "foreign copy pristine: {out}");
    assert_not_attested(&out.envelope, PURL, "not_applied");

    hosted::install_store(root, foreign, PATCHED);
    let out = run_vex(&binary(), root, &VexRun::online(&api));
    assert_eq!(out.code, Some(0), "every copy patched: {out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, VULNS);
}
