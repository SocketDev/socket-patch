//! The manifest-less VEX step every REAL-vlt hosted / vendored e2e flow ends
//! with (`e2e_redirect_vlt_build`, `e2e_vendor_vlt_build`,
//! `mode_migration_vlt`), plus the hermetic `e2e_vex_lockfile` vlt cells.
//!
//! Pull it in with (it re-exports the shared `vex_e2e_common` helper):
//!
//! ```ignore
//! #[path = "vex_e2e_common/vlt.rs"]
//! mod vlt_vex;
//! ```
//!
//! [`run_vlt_vex_matrix`] takes the project a flow left behind (its
//! committed state: package.json, `vlt-lock.json`, `vlt.json`, workspace
//! members, `.socket/`) and proves, on a FRESH CHECKOUT with
//! `.socket/manifest.json` deleted and a real `vlt ci` run by the caller's
//! closure:
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
//! 4. `reverted` — the lock (and, vendored, the importer package.json
//!    files) put back to the registry version (ledgers and committed
//!    artifacts kept, the patched install left in node_modules):
//!    NOT attested (`redirect_unwired` / `vendor_unwired`), also under
//!    `--no-verify`.
//!
//! The checkout copies what git would commit: the root `node_modules/` is
//! left out, and so is vlt's `node_modules/` inside a vendored package dir
//! (links only; the `<uuid>/.gitignore` excludes it).
//!
//! Each passed step prints `VLT-VEX <tag> <mode> <step> ok` so a matrix log
//! reads as a per-version results table.

#![allow(dead_code)]

use std::path::{Component, Path, PathBuf};

#[path = "mod.rs"]
mod common;
pub use common::*;

/// The lock every vlt flow commits.
pub const VLT_LOCK: &str = "vlt-lock.json";

/// Which wiring the flow produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VltMode {
    Hosted,
    Vendored,
}

impl VltMode {
    pub fn marker(self) -> Marker {
        match self {
            VltMode::Hosted => Marker::Redirected,
            VltMode::Vendored => Marker::Vendored,
        }
    }

    /// The omission a ledger-backed record gets once the lock no longer
    /// references it.
    pub fn unwired_reason(self) -> &'static str {
        match self {
            VltMode::Hosted => "redirect_unwired",
            VltMode::Vendored => "vendor_unwired",
        }
    }

    fn label(self) -> &'static str {
        match self {
            VltMode::Hosted => "hosted",
            VltMode::Vendored => "vendored",
        }
    }
}

/// What the flow patched and how to judge it.
pub struct VltVexCase<'a> {
    /// Log / directory tag (unique per call within one scratch dir).
    pub tag: &'a str,
    pub mode: VltMode,
    pub purl: &'a str,
    pub uuid: &'a str,
    /// The patch record's files: (`package/<path>`, afterHash).
    pub files: Vec<(String, String)>,
    /// Vulnerability ids (+ CVE aliases) the record carries — the flow's
    /// own mock / staged manifest must carry the same set.
    pub vulns: &'a [(&'a str, &'a [&'a str])],
    /// `vlt-lock.json` BEFORE the patch (the registry wiring) — the
    /// `reverted` step writes it back.
    pub registry_lock: Vec<u8>,
    /// Project-relative package.json files BEFORE a vendored wiring (their
    /// `file:` specs are wiring too); the `reverted` step writes them back.
    pub registry_manifests: Vec<(String, Vec<u8>)>,
    /// `--patch-server-url` for a hosted URL on a mock origin (a hosted ref
    /// counts only on a Socket host or the configured one).
    pub patch_server_url: Option<String>,
}

/// Whether root-relative `rel` is vlt's link dir inside a package dir
/// (`…/node_modules/[@s/]<name>/node_modules`), which git never commits.
fn is_nested_link_dir(rel: &Path) -> bool {
    let parts: Vec<&str> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();
    let Some((last, head)) = parts.split_last() else {
        return false;
    };
    if *last != "node_modules" {
        return false;
    }
    match head {
        [.., "node_modules", _] => true,
        [.., "node_modules", scope, _] => scope.starts_with('@'),
        _ => false,
    }
}

/// Copy `project`'s committable state into `dest`: everything except the
/// root `node_modules`, vlt's link dirs inside vendored packages, symlinks,
/// the manifest, the apply lock and prior VEX output.
pub fn manifestless_checkout(project: &Path, dest: &Path) -> PathBuf {
    fn walk(src: &Path, dst: &Path, root: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap();
            if rel == Path::new("node_modules")
                || is_nested_link_dir(rel)
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
/// checkout of `project` under `scratch`. `install` runs the REAL `vlt ci`
/// in the checkout (or, hermetically, stages its result) and asserts the
/// patched bytes landed. Runs on its own thread, so it is callable from
/// sync tests and from inside any tokio runtime alike (the mock API owns a
/// runtime).
pub fn run_vlt_vex_matrix<F>(project: &Path, scratch: &Path, case: &VltVexCase<'_>, install: F)
where
    F: FnOnce(&Path) + Send,
{
    outside_runtime(|| matrix(project, scratch, case, install))
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

/// [`assert_not_attested`] for either spelling of an npm scope: a purl the
/// record spells `pkg:npm/%40scope/pkg@v` is reported by lockfile discovery
/// in its canonical `pkg:npm/@scope/pkg@v` form.
pub fn assert_skipped<'a>(
    envelope: &'a serde_json::Value,
    purl: &str,
    reason: &str,
) -> &'a serde_json::Value {
    let canonical = purl.replace("%40", "@");
    let about =
        |e: &serde_json::Value, p: &str| e["purl"].as_str().is_some_and(|q| purl_matches(q, p));
    let events: Vec<&serde_json::Value> = envelope["events"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
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

fn matrix<F: FnOnce(&Path)>(project: &Path, scratch: &Path, case: &VltVexCase<'_>, install: F) {
    let bin = binary();
    let mode = case.mode;
    let what = format!("{} {}", case.tag, mode.label());
    let ok = |step: &str| eprintln!("VLT-VEX {} {} {step} ok", case.tag, mode.label());
    let checkout = manifestless_checkout(project, &scratch.join(format!("vex-{}", case.tag)));
    install(&checkout);
    let lock_path = checkout.join(VLT_LOCK);
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

    let out = run_vex(&bin, &checkout, &online());
    assert_eq!(out.code, Some(0), "{what} manifest-deleted: {out}");
    assert_attested(out.doc(), case.purl, case.uuid, mode.marker(), case.vulns);
    ok("manifest-deleted");
    let mut embedded = vec![VexVia::Apply];
    if mode == VltMode::Vendored {
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
            "{what} embedded {via:?} must not touch {VLT_LOCK}"
        );
        assert!(
            !checkout.join(".socket/manifest.json").exists(),
            "{what} embedded {via:?} must not write a manifest"
        );
        ok(&format!("embedded-{via:?}"));
    }

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
    for (rel, bytes) in &case.registry_manifests {
        std::fs::write(checkout.join(rel), bytes).unwrap();
    }
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

#[test]
fn nested_link_dirs_are_left_out_of_the_checkout() {
    for (rel, nested) in [
        ("node_modules", false),
        (
            ".socket/vendor/npm/u/a-1.0.0/node_modules/a/node_modules",
            true,
        ),
        (
            ".socket/vendor/npm/u/@s/a-1.0.0/node_modules/@s/a/node_modules",
            true,
        ),
        (".socket/vendor/npm/u/a-1.0.0/node_modules", false),
        (".socket/vendor/npm/u/a-1.0.0/node_modules/a", false),
        ("packages/a/node_modules", false),
    ] {
        assert_eq!(is_nested_link_dir(Path::new(rel)), nested, "{rel}");
    }
}
