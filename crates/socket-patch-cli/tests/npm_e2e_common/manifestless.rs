//! Manifest-less VEX tail + checkout helpers shared by every npm hosted /
//! vendored flow, with or without a real npm (no toolchain here, so suites
//! that already include `common/cache_env.rs` can pull in just this file):
//!
//! ```ignore
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! #[path = "npm_e2e_common/manifestless.rs"]
//! mod npm_manifestless;
//! ```
//!
//! (`npm_e2e_common/mod.rs` re-exports all of it for the real-npm suites.)

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::vex_e2e_common::{
    assert_absent, assert_attested, assert_not_attested, run_vex, seed_legacy_manifest,
    statements_for, strip_ledgers, strip_manifest, Marker, PatchApi, VexOutcome, VexRun, VexVia,
};

/// npm >= 12 needs `allow-remote=all` for a hosted redirect's lock (the
/// hosted run auto-configures it in the project `.npmrc`).
pub fn needs_allow_remote(major: u32) -> bool {
    major >= 12
}

pub fn copy_dir_recursive(src: &Path, dst: &Path) {
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

/// A new dir holding ONLY what a git checkout carries: package.json, the
/// committed `locks`, `.npmrc` when present, and `.socket/`.
pub fn fresh_checkout(src: &Path, dst: &Path, locks: &[&str]) {
    std::fs::create_dir_all(dst).unwrap();
    std::fs::copy(src.join("package.json"), dst.join("package.json")).unwrap();
    for lock in locks {
        std::fs::copy(src.join(lock), dst.join(lock)).unwrap();
    }
    if src.join(".npmrc").is_file() {
        std::fs::copy(src.join(".npmrc"), dst.join(".npmrc")).unwrap();
    }
    if src.join(".socket").is_dir() {
        copy_dir_recursive(&src.join(".socket"), &dst.join(".socket"));
    }
}

// ── manifest-less VEX tail ────────────────────────────────────────────

/// One manifest-less VEX pass over a committed + freshly installed npm
/// project (see [`manifestless_vex_matrix`]).
pub struct ManifestlessCase<'a> {
    /// Label for failure messages / the results table.
    pub label: String,
    /// The fresh checkout (patched bytes installed by the real npm).
    pub project: &'a Path,
    pub purl: &'a str,
    pub uuid: &'a str,
    pub marker: Marker,
    pub vulns: &'a [(&'a str, &'a [&'a str])],
    /// Serves the patch view for `uuid` (public-proxy route).
    pub api: &'a PatchApi,
    /// `--patch-server-url` (the hosted artifact origin — the mock stands
    /// in for patch.socket.dev, which is allowlisted in production).
    pub patch_server_url: Option<String>,
    /// The committed lock files and their pre-Socket (registry) bytes, for
    /// the revert cell.
    pub registry_locks: Vec<(&'a str, Vec<u8>)>,
    /// Also drive embedded `apply --vex` / `vendor --vex` (manifest-less).
    pub embedded: &'a [VexVia],
}

/// Per-cell outcome for the results table.
#[derive(Debug, Default, Clone)]
pub struct MatrixReport {
    pub cells: Vec<(&'static str, &'static str)>,
}

impl MatrixReport {
    fn pass(&mut self, cell: &'static str) {
        self.cells.push((cell, "pass"));
    }
}

impl std::fmt::Display for MatrixReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cells: Vec<String> = self
            .cells
            .iter()
            .map(|(cell, result)| format!("{cell}={result}"))
            .collect();
        write!(f, "{}", cells.join(" "))
    }
}

fn run(case: &ManifestlessCase<'_>, run: VexRun) -> VexOutcome {
    let mut run = run;
    run.patch_server_url = case.patch_server_url.clone();
    run_vex(&crate::vex_e2e_common::binary(), case.project, &run)
}

/// The manifest-less cells every npm hosted / vendored flow ends in:
///
/// 0. `legacy-manifest` (vendored only): the `.socket/manifest.json` a
///    pre-5.0 vendored run left beside its ledger (the ledger's embedded
///    records) → standalone `vex` attests the same way;
/// 1. `manifest-deleted`: `.socket/manifest.json` removed (ledgers kept) →
///    standalone `vex` attests the purl with the right marker + vuln ids
///    (and every `embedded` command does too);
/// 2. `ledgers-deleted`: both ledgers removed too → still attested, from
///    lockfile discovery + the patch API (≥ 1 view request);
/// 3. `offline`: no ledgers, `--offline` → `record_unavailable`, ZERO
///    requests;
/// 4. `reverted`: ledgers restored, locks reverted to their registry bytes
///    → NOT attested (default and `--no-verify`); with the ledgers gone as
///    well nothing names the patch at all.
///
/// Leaves the project reverted (locks at registry bytes, no ledgers).
pub fn manifestless_vex_matrix(case: &ManifestlessCase<'_>) -> MatrixReport {
    let mut report = MatrixReport::default();
    let label = &case.label;
    let p = case.project;
    let ledger_paths = [
        socket_patch_core::vendor::VENDOR_STATE_REL,
        socket_patch_core::patch::redirect::REDIRECT_STATE_REL,
    ];
    let ledgers: Vec<(&str, Vec<u8>)> = ledger_paths
        .iter()
        .filter_map(|rel| std::fs::read(p.join(rel)).ok().map(|b| (*rel, b)))
        .collect();
    assert!(
        !ledgers.is_empty(),
        "[{label}] the flow must have written a ledger"
    );

    // 0. a LEGACY vendored checkout: vendored mode is manifest-free now,
    //    but a pre-5.0 run left the record in `.socket/manifest.json`
    //    beside the ledger — same uuid, so it attests the same way.
    if case.marker == Marker::Vendored {
        assert!(
            seed_legacy_manifest(p) > 0,
            "[{label}] the vendor ledger embeds the record"
        );
        let out = run(case, VexRun::online(case.api));
        assert_eq!(out.code, Some(0), "[{label}] legacy-manifest:\n{out}");
        assert_attested(out.doc(), case.purl, case.uuid, case.marker, case.vulns);
        report.pass("legacy-manifest");
    }

    // 1. manifest deleted, ledgers kept.
    strip_manifest(p);
    let out = run(case, VexRun::online(case.api));
    assert_eq!(out.code, Some(0), "[{label}] manifest-deleted:\n{out}");
    assert_attested(out.doc(), case.purl, case.uuid, case.marker, case.vulns);
    for via in case.embedded {
        let out = run(case, VexRun::online(case.api).via(*via));
        assert_eq!(out.code, Some(0), "[{label}] embedded {via:?}:\n{out}");
        assert_attested(out.doc(), case.purl, case.uuid, case.marker, case.vulns);
        assert_eq!(
            out.envelope["status"], "noManifest",
            "[{label}] embedded {via:?} keeps the noManifest status:\n{out}"
        );
        assert!(
            out.envelope["vex"]["statements"].as_u64() >= Some(1),
            "[{label}] embedded {via:?} vex summary:\n{out}"
        );
    }
    report.pass("manifest-deleted");

    // 2. ledgers deleted too: lockfile discovery + the API.
    strip_ledgers(p);
    let before = case.api.view_requests(case.uuid);
    let out = run(case, VexRun::online(case.api));
    assert_eq!(out.code, Some(0), "[{label}] ledgers-deleted:\n{out}");
    assert_attested(out.doc(), case.purl, case.uuid, case.marker, case.vulns);
    assert!(
        case.api.view_requests(case.uuid) > before,
        "[{label}] the record must come from the patch API: {:?}",
        case.api.requests()
    );
    for via in case.embedded {
        let out = run(case, VexRun::online(case.api).via(*via));
        assert_eq!(
            out.code,
            Some(0),
            "[{label}] embedded {via:?} no ledgers:\n{out}"
        );
        assert_attested(out.doc(), case.purl, case.uuid, case.marker, case.vulns);
    }
    report.pass("ledgers-deleted");

    // 3. offline with no ledgers: record unavailable, zero network.
    let before = case.api.request_count();
    let out = run(case, VexRun::offline());
    assert_eq!(out.code, Some(1), "[{label}] offline:\n{out}");
    assert_not_attested(&out.envelope, case.purl, "record_unavailable");
    assert_absent(out.doc.as_ref(), case.purl);
    assert_eq!(
        case.api.request_count(),
        before,
        "[{label}] --offline must make zero requests: {:?}",
        case.api.requests()
    );
    report.pass("offline");

    // 4. lockfile reverted to the registry version, ledgers + artifacts
    //    kept: the stale ledger must not keep attesting — verify or not.
    for (rel, bytes) in &ledgers {
        std::fs::write(p.join(rel), bytes).unwrap();
    }
    for (lock, bytes) in &case.registry_locks {
        std::fs::write(p.join(lock), bytes).unwrap();
    }
    let unwired = match case.marker {
        Marker::Vendored => "vendor_unwired",
        _ => "redirect_unwired",
    };
    for no_verify in [false, true] {
        let mut r = VexRun::online(case.api);
        r.no_verify = no_verify;
        let out = run(case, r);
        assert_ne!(
            out.code,
            Some(0),
            "[{label}] reverted (no_verify={no_verify}):\n{out}"
        );
        assert_absent(out.doc.as_ref(), case.purl);
        assert_not_attested(&out.envelope, case.purl, unwired);
    }
    strip_ledgers(p);
    let out = run(case, VexRun::online(case.api));
    assert_ne!(out.code, Some(0), "[{label}] reverted, no ledgers:\n{out}");
    assert_absent(out.doc.as_ref(), case.purl);
    report.pass("reverted");
    report
}

/// [`manifestless_vex_matrix`] against the REAL patch API (the anonymous
/// public proxy — the production suites' surface): the record's vuln set is
/// production data, so a cell asserts only that `purl` is attested
/// `not_affected` with `marker` for at least `must_include` (a GHSA id).
/// Cells: ledgers kept, ledgers deleted, `--offline`, lock reverted.
pub fn production_manifestless_vex(
    label: &str,
    project: &Path,
    purl: &str,
    uuid: &str,
    marker: Marker,
    must_include: &str,
    registry_locks: &[(&str, Vec<u8>)],
) -> MatrixReport {
    let mut report = MatrixReport::default();
    let bin = crate::vex_e2e_common::binary();
    let part = match marker {
        Marker::Vendored => format!("Patched via Socket patch {uuid} (vendored)"),
        _ => format!("Patched via Socket patch {uuid} (redirected)"),
    };
    let attested = |out: &VexOutcome, cell: &str| {
        assert_eq!(out.code, Some(0), "[{label}] {cell}:\n{out}");
        let st = statements_for(out.doc(), purl);
        assert!(
            st.iter()
                .any(|s| s["vulnerability"]["name"] == must_include),
            "[{label}] {cell}: {must_include} not attested:\n{out}"
        );
        for s in &st {
            assert_eq!(s["status"], "not_affected", "[{label}] {cell}: {s:#}");
            let impact = s["impact_statement"].as_str().unwrap_or_default();
            assert!(
                impact.split("; ").any(|p| p == part),
                "[{label}] {cell}: impact {impact:?} lacks the wired patch's {marker:?} clause"
            );
        }
    };
    let ledgers: Vec<(&str, Vec<u8>)> = [
        socket_patch_core::vendor::VENDOR_STATE_REL,
        socket_patch_core::patch::redirect::REDIRECT_STATE_REL,
    ]
    .iter()
    .filter_map(|rel| std::fs::read(project.join(rel)).ok().map(|b| (*rel, b)))
    .collect();
    strip_manifest(project);
    attested(
        &run_vex(&bin, project, &VexRun::default()),
        "manifest-deleted",
    );
    report.pass("manifest-deleted");
    strip_ledgers(project);
    attested(
        &run_vex(&bin, project, &VexRun::default()),
        "ledgers-deleted",
    );
    report.pass("ledgers-deleted");
    let out = run_vex(&bin, project, &VexRun::offline());
    assert_eq!(out.code, Some(1), "[{label}] offline:\n{out}");
    assert_not_attested(&out.envelope, purl, "record_unavailable");
    report.pass("offline");
    for (rel, bytes) in &ledgers {
        std::fs::write(project.join(rel), bytes).unwrap();
    }
    for (lock, bytes) in registry_locks {
        std::fs::write(project.join(lock), bytes).unwrap();
    }
    for no_verify in [false, true] {
        let run = VexRun {
            no_verify,
            ..VexRun::default()
        };
        let out = run_vex(&bin, project, &run);
        assert_ne!(out.code, Some(0), "[{label}] reverted:\n{out}");
        assert_absent(out.doc.as_ref(), purl);
    }
    report.pass("reverted");
    report
}

/// Absolute path of the pinned-matrix results file a leg appends its row to
/// (`SOCKET_PATCH_NPM_E2E_RESULTS`), if configured.
pub fn record_results(row: &str) {
    println!("NPM-MATRIX {row}");
    if let Some(path) = std::env::var_os("SOCKET_PATCH_NPM_E2E_RESULTS").filter(|v| !v.is_empty()) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(PathBuf::from(path))
            .unwrap();
        writeln!(f, "{row}").unwrap();
    }
}
