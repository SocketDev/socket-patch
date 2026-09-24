//! Toolchain gating + the manifest-less VEX tail shared by the real-go e2e
//! suites (`e2e_golang_hosted_build`, `e2e_vendor_golang_build`,
//! `e2e_golang_build`, `e2e_golang_workspace_build`), so one local loop (or
//! one CI matrix leg per Go release) drives every hosted + vendored flow
//! through a given `go` and ends each in manifest-less `socket-patch vex`.
//!
//! Go has a single major (1.x); the matrix is the oldest release the flows
//! support (1.18 — the first with `go.work`), a middle line (1.21 — the
//! `GOTOOLCHAIN` / `toolchain` era, and the docker image's pin) and the
//! newest. The release is chosen by whichever `go` is first on `PATH`
//! (`actions/setup-go` in CI, a golang.org/dl SDK's `bin/` locally) —
//! never a wrapper name, so the CLI under test and every fixture step see
//! the same toolchain:
//!
//! * `SOCKET_PATCH_GO_E2E_VERSION` — the release the leg must run (`1.18`,
//!   `1.21.13`, …; a prefix of `go version`'s `go1.X.Y`). When set, the
//!   suites assert `go version` really is that release, so a leg can never
//!   go green on the wrong toolchain.
//! * `SOCKET_PATCH_GO_E2E_REQUIRED=1` — turn the soft skips (`go` / `zip`
//!   missing) into failures.
//!
//! Local sweep (see `go install golang.org/dl/go1.X.Y@latest && go1.X.Y
//! download`, which unpacks into `~/sdk/go1.X.Y`):
//!
//! ```sh
//! for v in 1.18.10 1.21.13 1.24.13 1.26.3; do
//!   PATH="$HOME/sdk/go$v/bin:$PATH" SOCKET_PATCH_GO_E2E_VERSION=$v \
//!   SOCKET_PATCH_GO_E2E_REQUIRED=1 \
//!   cargo test -p socket-patch-cli --test e2e_golang_hosted_build \
//!     --test e2e_vendor_golang_build --test e2e_golang_build \
//!     --test e2e_golang_workspace_build
//! done
//! ```
//!
//! [`manifestless_vex`] is the tail every flow runs once it has produced its
//! committed state: a fresh checkout with the manifest deleted and a REAL
//! `go` install, then standalone and embedded VEX over it — with ledgers,
//! without them, offline, and with the wiring reverted.

#![allow(dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::vex_e2e_common::*;

pub const VERSION_ENV: &str = "SOCKET_PATCH_GO_E2E_VERSION";
pub const REQUIRED_ENV: &str = "SOCKET_PATCH_GO_E2E_REQUIRED";

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn required() -> bool {
    env_nonempty(REQUIRED_ENV).is_some()
}

/// `go version`'s release token (`go1.21.13`), or `None` when `go` does not
/// run. `GOTOOLCHAIN=local`: a toolchain switch (1.21+) must not answer for
/// the `go` under test.
pub fn go_release() -> Option<String> {
    let out = Command::new("go")
        .arg("version")
        .env("GOTOOLCHAIN", "local")
        .env("GOENV", "off")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|t| t.starts_with("go1."))
        .map(str::to_string)
}

/// `(1, minor)` of the `go` under test (panics when there is none).
pub fn go_minor() -> u32 {
    let release = go_release().expect("go runs");
    release
        .trim_start_matches("go1.")
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or_else(|| panic!("unparseable go release {release:?}"))
}

fn has(cmd: &str, arg: &str) -> bool {
    Command::new(cmd)
        .arg(arg)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Gate for a real-go test: `false` (after printing why) when `go` / `zip`
/// are missing and the leg is not REQUIRED; panics when REQUIRED; asserts
/// the pinned release. Prints the release so every log names it.
pub fn toolchain_ready(suite: &str) -> bool {
    let release = go_release();
    let zip = has("zip", "-v");
    if release.is_none() || !zip {
        assert!(
            !required(),
            "{REQUIRED_ENV} is set but `go version` / `zip` did not run ({suite})"
        );
        eprintln!("SKIP {suite}: `go`/`zip` not installed");
        return false;
    }
    let release = release.expect("checked");
    if let Some(want) = env_nonempty(VERSION_ENV) {
        let want = want.trim_start_matches("go");
        let got = release.trim_start_matches("go");
        assert!(
            got == want || got.starts_with(&format!("{want}.")),
            "{VERSION_ENV}={want} but `go version` reports {release} ({suite})"
        );
    }
    eprintln!("{suite}: running under {release}");
    true
}

/// The `go` directive fixture go.mod files declare: `1.21` (what the suites
/// were written against) unless the toolchain under test is older — a
/// pre-1.21 `go mod tidy` refuses a go.mod newer than itself ("maximum
/// version supported by tidy is 1.18"), and a real project on that
/// toolchain would never declare one.
pub fn go_directive() -> &'static str {
    if go_minor() >= 21 {
        "1.21"
    } else {
        "1.18"
    }
}

/// `go.work` needs Go 1.18+ — true below the whole matrix, but a hand-run
/// with an ancient `go` skips the workspace flows instead of failing them.
pub fn supports_go_work() -> bool {
    go_minor() >= 18
}

// ── fresh checkouts ───────────────────────────────────────────────────

/// Copy `src` (the committed project: go.mod/go.sum/go.work/sources and the
/// whole `.socket/`) to `dst`, the way a fresh clone sees it. Build outputs
/// and VEX documents from the flow are left behind.
pub fn checkout(src: &Path, dst: &Path) {
    copy_tree(src, dst);
    for stale in [DEFAULT_OUTPUT, "app", "out.vex.json"] {
        let _ = std::fs::remove_file(dst.join(stale));
    }
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        let ty = entry.file_type().unwrap();
        if ty.is_dir() {
            copy_tree(&entry.path(), &to);
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &to).unwrap();
            // Module-cache extractions are read-only; a copy must stay
            // writable so the step can edit / delete it.
            let mut perms = std::fs::metadata(&to).unwrap().permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            std::fs::set_permissions(&to, perms).unwrap();
        }
    }
}

pub fn has_ledger(project: &Path) -> bool {
    project
        .join(socket_patch_core::vendor::VENDOR_STATE_REL)
        .is_file()
        || project
            .join(socket_patch_core::patch::redirect::REDIRECT_STATE_REL)
            .is_file()
}

// ── the manifest-less VEX tail ─────────────────────────────────────────

/// One flow's manifest-less VEX tail.
pub struct ManifestlessGo<'a> {
    /// Log label (`"hosted/get"`, `"vendored/go.work"`, …).
    pub label: &'a str,
    /// The flow's committed project (never modified).
    pub committed: &'a Path,
    /// Scratch dir for the fresh checkouts.
    pub scratch: &'a Path,
    pub purl: &'a str,
    pub uuid: &'a str,
    pub marker: Marker,
    pub vulns: &'a [(&'a str, &'a [&'a str])],
    /// The API's view of the patch (what the flow's record says).
    pub view: serde_json::Value,
    /// REAL install in a fresh checkout (`go build` / `go mod download`
    /// with a fresh module cache); returns the `GOMODCACHE` VEX should see.
    /// Must also prove the build links the patched bytes.
    pub install: &'a dyn Fn(&Path) -> PathBuf,
    /// Point the checkout's wiring back at the registry module (the
    /// pre-patch go.mod/go.sum/go.work), keeping `.socket/` (ledgers and
    /// artifacts); may reinstall. Returns the `GOMODCACHE` VEX should see.
    pub revert: &'a dyn Fn(&Path) -> PathBuf,
    /// Skip reason the reverted checkout must carry while a ledger remains
    /// (`redirect_unwired` / `vendor_unwired`).
    pub unwired_reason: &'a str,
    /// Tamper with the bytes the build consumes (the patched module in the
    /// install's `GOMODCACHE` for hosted, the committed artifact member for
    /// vendored) — `(checkout, modcache)`; VEX must then omit the patch
    /// with `tamper_reason` (anti-vacuity: the install is really hashed).
    pub tamper: &'a dyn Fn(&Path, &Path),
    pub tamper_reason: &'a str,
    /// Embedded commands to exercise on the ledger-less checkout
    /// (`Apply`, `Vendor`, `Scan` — the ones the flow itself uses).
    pub embedded: &'a [VexVia],
}

/// Results of one tail (for the per-version table the suites print).
#[derive(Debug, Default)]
pub struct TailReport {
    pub manifest_deleted: bool,
    pub ledger_offline: Option<bool>,
    pub ledgers_deleted: bool,
    pub offline: bool,
    pub tampered: bool,
    pub reverted: bool,
}

fn go_envs(modcache: &Path) -> Vec<(String, OsString)> {
    vec![
        ("GOMODCACHE".into(), modcache.as_os_str().to_owned()),
        // An ambient GOPATH / GOFLAGS must not add a second module cache.
        (
            "GOPATH".into(),
            modcache.join("__no_gopath__").into_os_string(),
        ),
        ("GOFLAGS".into(), OsString::new()),
    ]
}

fn run(project: &Path, modcache: &Path, base: VexRun) -> VexOutcome {
    let mut run = base;
    run.product = Some("pkg:golang/example.com/consumer@v0.0.1".into());
    run.envs.extend(go_envs(modcache));
    run_vex(&binary(), project, &run)
}

/// Run the tail; panics (with the full CLI output) on the first wrong
/// verdict. Steps, in order:
///
/// 1. fresh checkout, manifest deleted, real install → online `vex`
///    attests with the flow's marker + vuln ids; with the flow's ledgers
///    still present, `--offline` attests too (the ledger embeds the record)
///    with zero API requests;
/// 2. ledgers deleted → online `vex` still attests (go.mod/go.work wiring +
///    the API record), and so does every requested embedded command;
/// 3. `--offline` with no ledgers → `record_unavailable`, zero requests;
///    then the consumed bytes tampered → omitted (`tamper_reason`);
/// 4. a second fresh checkout (ledgers kept) with the wiring reverted →
///    NOT attested (`unwired_reason`), under `--no-verify` too; with no
///    ledger at all nothing is discovered (exit 2).
pub fn manifestless_vex(case: &ManifestlessGo<'_>) -> TailReport {
    let label = case.label;
    let mut report = TailReport::default();
    let api = PatchApi::start(vec![(case.uuid.to_string(), case.view.clone())]);
    let attest = |out: &VexOutcome, what: &str| {
        assert_eq!(out.code, Some(0), "[{label}] {what}\n{out}");
        assert_attested(out.doc(), case.purl, case.uuid, case.marker, case.vulns);
        // Go's module cache is immutable and never consumed under a Socket
        // replace: its pristine `M@v` is not drift to disclose.
        let warnings = out.envelope["warnings"].to_string();
        assert!(
            !warnings.contains("vendored_tree_out_of_sync"),
            "[{label}] {what}: spurious out-of-sync disclosure\n{out}"
        );
        assert!(
            !out.output
                .parent()
                .unwrap()
                .join(".socket/manifest.json")
                .exists(),
            "[{label}] {what}: vex never writes the manifest"
        );
    };

    // ── 1. manifest deleted ──────────────────────────────────────────
    let fresh = case.scratch.join(format!("vex-fresh-{}", slug(label)));
    checkout(case.committed, &fresh);
    strip_manifest(&fresh);
    let modcache = (case.install)(&fresh);
    let flow_ledger = has_ledger(&fresh);
    let out = run(&fresh, &modcache, VexRun::online(&api));
    attest(&out, "manifest deleted, online");
    report.manifest_deleted = true;
    if flow_ledger {
        let before = api.request_count();
        let out = run(&fresh, &modcache, VexRun::offline());
        attest(&out, "manifest deleted, ledger kept, --offline");
        assert_eq!(
            api.request_count(),
            before,
            "[{label}] --offline made API requests"
        );
        report.ledger_offline = Some(true);
    }

    // ── 2. ledgers deleted ───────────────────────────────────────────
    strip_ledgers(&fresh);
    let before = api.view_requests(case.uuid);
    let out = run(&fresh, &modcache, VexRun::online(&api));
    attest(&out, "ledgers deleted, online");
    assert!(
        api.view_requests(case.uuid) > before,
        "[{label}] the record must come from the API once the ledgers are gone"
    );
    for via in case.embedded {
        let out = run(&fresh, &modcache, VexRun::online(&api).via(*via));
        attest(&out, &format!("ledgers deleted, embedded {via:?}"));
    }
    report.ledgers_deleted = true;

    // ── 3. offline, no ledgers ───────────────────────────────────────
    let before = api.request_count();
    let out = run(&fresh, &modcache, VexRun::offline());
    assert_eq!(out.code, Some(1), "[{label}] offline, no ledgers\n{out}");
    assert_not_attested(&out.envelope, case.purl, "record_unavailable");
    assert_absent(out.doc.as_ref(), case.purl);
    assert_eq!(
        api.request_count(),
        before,
        "[{label}] --offline made API requests"
    );
    report.offline = true;

    // ── 3b. tampered install → omitted (the verdict hashes real bytes) ─
    (case.tamper)(&fresh, &modcache);
    let out = run(&fresh, &modcache, VexRun::online(&api));
    assert_eq!(out.code, Some(1), "[{label}] tampered\n{out}");
    assert_not_attested(&out.envelope, case.purl, case.tamper_reason);
    assert_absent(out.doc.as_ref(), case.purl);
    report.tampered = true;

    // ── 4. wiring reverted, ledgers + artifacts kept ─────────────────
    let reverted = case.scratch.join(format!("vex-reverted-{}", slug(label)));
    checkout(case.committed, &reverted);
    strip_manifest(&reverted);
    let modcache = (case.revert)(&reverted);
    for no_verify in [false, true] {
        let base = VexRun {
            no_verify,
            ..VexRun::online(&api)
        };
        let out = run(&reverted, &modcache, base);
        assert_absent(out.doc.as_ref(), case.purl);
        if flow_ledger {
            assert_eq!(
                out.code,
                Some(1),
                "[{label}] reverted (no_verify={no_verify})\n{out}"
            );
            assert_not_attested(&out.envelope, case.purl, case.unwired_reason);
        } else {
            assert_eq!(
                out.code,
                Some(2),
                "[{label}] reverted, nothing wired (no_verify={no_verify})\n{out}"
            );
            assert_eq!(
                out.envelope["error"]["code"], "manifest_not_found",
                "[{label}] {out}"
            );
        }
    }
    report.reverted = true;
    eprintln!("[{label}] manifest-less vex tail: {report:?}");
    report
}

fn slug(label: &str) -> String {
    label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Overwrite `file` (possibly inside a read-only module-cache extraction).
pub fn overwrite(file: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    assert!(
        file.is_file(),
        "{} must exist to be tampered",
        file.display()
    );
    let dir = file.parent().unwrap();
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    let _ = std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644));
    std::fs::write(file, bytes).unwrap();
}
