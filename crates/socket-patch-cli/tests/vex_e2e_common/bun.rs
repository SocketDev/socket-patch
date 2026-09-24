//! The manifest-less VEX step every REAL-bun hosted / vendored e2e flow ends
//! with (`e2e_redirect_bun_build`, `e2e_vendor_bun_build`,
//! `mode_migration_bun`, `e2e_bun_lockb`, plus the hermetic
//! `in_process_vendor_bun*` twins).
//!
//! Pull it in with (it re-exports the shared `vex_e2e_common` helper):
//!
//! ```ignore
//! #[path = "vex_e2e_common/bun.rs"]
//! mod bun_vex;
//! ```
//!
//! [`run_bun_vex_matrix`] takes the project a flow left behind (its
//! committed state: package.json, `bun.lock` / `bun.lockb`, bunfig, workspace
//! members, `.socket/`) and proves, on a FRESH CHECKOUT with
//! `.socket/manifest.json` deleted and a real `bun install` run by the
//! caller's closure:
//!
//! 1. `manifest-deleted` — standalone `vex --json --output` against a mock
//!    patch API attests the patched purl with the right `(redirected)` /
//!    `(vendored)` marker and exactly the expected vulnerability ids (+ CVE
//!    aliases); the embedded `apply --vex` (and, vendored, `vendor --vex`)
//!    attest the same without touching the lock.
//! 2. `ledgers-deleted` — `.socket/vendor/state.json` and
//!    `redirect-state.json` deleted too: still attested, now from lockfile
//!    discovery + the patch API (the view route is hit).
//! 3. `offline` — `--offline` with no ledgers: `record_unavailable`, exit 1,
//!    ZERO requests to the API.
//! 4. `reverted` — the lock put back to the registry version (ledgers and
//!    committed artifacts kept, the patched install left in node_modules):
//!    NOT attested (`redirect_unwired` / `vendor_unwired`), also under
//!    `--no-verify`.
//!
//! Each passed step prints `BUN-VEX <tag> <mode> <step> ok` so a matrix log
//! reads as a per-version results table.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

// The shared helper, re-exported: a suite includes ONLY this module
// (`bun_vex::run_vex`, `bun_vex::PatchApi`, …), so no `mod vex_e2e_common`
// line is needed next to it.
#[path = "mod.rs"]
mod common;
pub use common::*;

/// Which wiring the flow produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BunMode {
    Hosted,
    Vendored,
}

impl BunMode {
    pub fn marker(self) -> Marker {
        match self {
            BunMode::Hosted => Marker::Redirected,
            BunMode::Vendored => Marker::Vendored,
        }
    }

    /// The omission a ledger-backed record gets once the lock no longer
    /// references it.
    pub fn unwired_reason(self) -> &'static str {
        match self {
            BunMode::Hosted => "redirect_unwired",
            BunMode::Vendored => "vendor_unwired",
        }
    }

    fn label(self) -> &'static str {
        match self {
            BunMode::Hosted => "hosted",
            BunMode::Vendored => "vendored",
        }
    }
}

/// What the flow patched and how to judge it.
pub struct BunVexCase<'a> {
    /// Log / directory tag (unique per call within one scratch dir).
    pub tag: &'a str,
    pub mode: BunMode,
    pub purl: &'a str,
    pub uuid: &'a str,
    /// The patch record's files: (`package/<path>`, afterHash).
    pub files: Vec<(String, String)>,
    /// Vulnerability ids (+ CVE aliases) the record carries — the flow's
    /// own mock / staged manifest must carry the same set.
    pub vulns: &'a [(&'a str, &'a [&'a str])],
    /// The lock the project commits: `bun.lock` or `bun.lockb`.
    pub lock: &'a str,
    /// That lock's bytes BEFORE the patch (the registry wiring) — the
    /// `reverted` step writes them back.
    pub registry_lock: Vec<u8>,
    /// `--patch-server-url` for a hosted URL on a mock origin (a hosted ref
    /// counts only on a Socket host or the configured one).
    pub patch_server_url: Option<String>,
}

/// Copy `project`'s committable state into `dest`: everything except
/// `node_modules`, the manifest, the apply lock and prior VEX output.
pub fn manifestless_checkout(project: &Path, dest: &Path) -> PathBuf {
    fn walk(src: &Path, dst: &Path, root: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap();
            if name == "node_modules"
                || rel == Path::new(".socket/manifest.json")
                || rel == Path::new(".socket/apply.lock")
                || rel == Path::new(DEFAULT_OUTPUT)
            {
                continue;
            }
            let ty = entry.file_type().unwrap();
            if ty.is_dir() {
                walk(&path, &dst.join(&name), root);
            } else if ty.is_file() {
                std::fs::copy(&path, dst.join(&name)).unwrap();
            }
        }
    }
    if dest.exists() {
        std::fs::remove_dir_all(dest).unwrap();
    }
    walk(project, dest, project);
    assert!(
        !dest.join(".socket/manifest.json").exists(),
        "the checkout must carry no manifest"
    );
    dest.to_path_buf()
}

fn ledger_paths(root: &Path) -> [PathBuf; 2] {
    [
        root.join(socket_patch_core::vendor::VENDOR_STATE_REL),
        root.join(socket_patch_core::patch::redirect::REDIRECT_STATE_REL),
    ]
}

/// Run the four-step manifest-less VEX matrix (module doc) on a fresh
/// checkout of `project` under `scratch`. `install` runs the REAL package
/// manager in the checkout (frozen, empty cache) and asserts the patched
/// bytes landed. Runs on its own thread, so it is callable from sync tests
/// and from inside any tokio runtime alike (the mock API owns a runtime).
pub fn run_bun_vex_matrix<F>(project: &Path, scratch: &Path, case: &BunVexCase<'_>, install: F)
where
    F: FnOnce(&Path) + Send,
{
    outside_runtime(|| matrix(project, scratch, case, install))
}

/// [`assert_not_attested`] for either spelling of an npm scope: a purl the
/// record spells `pkg:npm/%40scope/pkg@v` is reported by lockfile discovery
/// in its canonical `pkg:npm/@scope/pkg@v` form.
pub fn assert_skipped<'a>(
    envelope: &'a serde_json::Value,
    purl: &str,
    reason: &str,
) -> &'a serde_json::Value {
    let canonical = purl.replace("%40", "@");
    let events: Vec<&serde_json::Value> = envelope["events"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    let about =
        |e: &serde_json::Value, p: &str| e["purl"].as_str().is_some_and(|q| purl_matches(q, p));
    assert!(
        !events
            .iter()
            .any(|e| e["action"] == "verified" && (about(e, purl) || about(e, &canonical))),
        "{purl} was attested: {envelope:#}"
    );
    let chosen = if events.iter().any(|e| about(e, purl)) {
        purl
    } else {
        canonical.as_str()
    };
    assert_not_attested(envelope, chosen, reason)
}

/// Run `f` on its own thread: the mock [`PatchApi`] owns a tokio runtime,
/// which cannot be driven (or dropped) from inside another runtime.
pub fn outside_runtime<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|s| {
        s.spawn(f)
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

fn matrix<F: FnOnce(&Path)>(project: &Path, scratch: &Path, case: &BunVexCase<'_>, install: F) {
    let bin = binary();
    let mode = case.mode;
    let what = format!("{} {}", case.tag, mode.label());
    let ok = |step: &str| eprintln!("BUN-VEX {} {} {step} ok", case.tag, mode.label());
    let checkout = manifestless_checkout(project, &scratch.join(format!("vex-{}", case.tag)));
    install(&checkout);
    let lock_path = checkout.join(case.lock);
    let wired_lock = std::fs::read(&lock_path).unwrap();

    let files: Vec<(&str, &str)> = case
        .files
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let api = PatchApi::start(vec![(
        case.uuid.to_string(),
        patch_view(case.uuid, case.purl, &files, case.vulns),
    )]);
    let online = || VexRun {
        patch_server_url: case.patch_server_url.clone(),
        ..VexRun::online(&api)
    };

    // 1. Manifest deleted, ledgers kept.
    let out = run_vex(&bin, &checkout, &online());
    assert_eq!(out.code, Some(0), "{what} manifest-deleted: {out}");
    assert_attested(out.doc(), case.purl, case.uuid, mode.marker(), case.vulns);
    ok("manifest-deleted");
    let mut embedded = vec![VexVia::Apply];
    if mode == BunMode::Vendored {
        embedded.push(VexVia::Vendor);
    }
    for via in embedded {
        let out = run_vex(&bin, &checkout, &online().via(via));
        assert_eq!(out.code, Some(0), "{what} embedded {via:?}: {out}");
        assert_eq!(
            out.envelope["status"], "noManifest",
            "{what} embedded {via:?}: {out}"
        );
        assert_attested(out.doc(), case.purl, case.uuid, mode.marker(), case.vulns);
        assert_eq!(
            std::fs::read(&lock_path).unwrap(),
            wired_lock,
            "{what} embedded {via:?} must not touch {}",
            case.lock
        );
        assert!(
            !checkout.join(".socket/manifest.json").exists(),
            "{what} embedded {via:?} must not write a manifest"
        );
        ok(&format!("embedded-{via:?}"));
    }

    // 2. Ledgers deleted as well: lockfile discovery + the patch API.
    let ledgers: Vec<(PathBuf, Option<Vec<u8>>)> = ledger_paths(&checkout)
        .into_iter()
        .map(|p| {
            let bytes = std::fs::read(&p).ok();
            (p, bytes)
        })
        .collect();
    strip_ledgers(&checkout);
    let views_before = api.view_requests(case.uuid);
    let out = run_vex(&bin, &checkout, &online());
    assert_eq!(out.code, Some(0), "{what} ledgers-deleted: {out}");
    assert_attested(out.doc(), case.purl, case.uuid, mode.marker(), case.vulns);
    assert!(
        api.view_requests(case.uuid) > views_before,
        "{what} ledgers-deleted: the record must come from the patch API: {:?}",
        api.requests()
    );
    ok("ledgers-deleted");

    // 3. Offline, no ledgers: nothing to build a statement from, no network.
    let requests_before = api.request_count();
    let out = run_vex(
        &bin,
        &checkout,
        &VexRun {
            patch_server_url: case.patch_server_url.clone(),
            ..VexRun::offline()
        },
    );
    assert_eq!(out.code, Some(1), "{what} offline: {out}");
    assert_skipped(&out.envelope, case.purl, "record_unavailable");
    assert_absent(out.doc.as_ref(), case.purl);
    assert_eq!(
        api.request_count(),
        requests_before,
        "{what} offline must make zero API requests: {:?}",
        api.requests()
    );
    ok("offline");

    // 4. Lock reverted to the registry; ledgers + artifacts + the patched
    //    install stay behind. Leftovers never attest, verified or not.
    for (path, bytes) in &ledgers {
        if let Some(bytes) = bytes {
            std::fs::write(path, bytes).unwrap();
        }
    }
    assert!(
        ledgers.iter().any(|(_, b)| b.is_some()),
        "{what}: the flow left no ledger — the reverted step would be vacuous"
    );
    std::fs::write(&lock_path, &case.registry_lock).unwrap();
    for no_verify in [false, true] {
        let run = VexRun {
            no_verify,
            ..online()
        };
        let out = run_vex(&bin, &checkout, &run);
        assert_eq!(
            out.code,
            Some(1),
            "{what} reverted (no_verify={no_verify}): {out}"
        );
        assert_skipped(&out.envelope, case.purl, mode.unwired_reason());
        assert_absent(out.doc.as_ref(), case.purl);
    }
    ok("reverted");
}
