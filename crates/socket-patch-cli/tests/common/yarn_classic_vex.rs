//! yarn classic (v1) release selection and the manifest-less VEX steps the
//! real-yarn-classic suites share.
//!
//! Every real-yarn-classic suite (`e2e_redirect_yarn_classic_build`,
//! `e2e_vendor_yarn_classic_build`, `e2e_vendor_yarn_classic_dev_flow`,
//! `mode_migration_npm`'s classic legs and the two `*_production` legs)
//! installs through `corepack yarn@<version>`. The release is
//! [`DEFAULT_YARN_CLASSIC_VERSION`] unless [`VERSION_ENV`] names another 1.x
//! release, so one suite can be replayed across the classic line:
//!
//! ```sh
//! SOCKET_PATCH_YARN_CLASSIC_E2E_VERSION=1.0.2 SOCKET_PATCH_YARN_E2E_REQUIRED=1 \
//!   cargo test -p socket-patch-cli --test e2e_vendor_yarn_classic_build
//! ```
//!
//! (`scripts/yarn-classic-vex-matrix.sh` loops every suite over the release
//! list.) Under [`REQUIRED_ENV`]`=1` a missing or wrong yarn is a failure,
//! never a skip — the gate is [`require_yarn_classic`].
//!
//! [`ManifestlessVex::run`] is the step each flow appends once it has
//! produced its committed state and a REAL yarn has installed it into a
//! fresh checkout: the depscan / never-committed-`.socket/manifest.json`
//! shape, attested from the lockfile wiring alone.
//!
//! Pull it in AFTER the shared vex helper (it refers to it by that name):
//!
//! ```ignore
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! #[path = "common/yarn_classic_vex.rs"]
//! mod yarn_classic_vex;
//! ```

#![allow(dead_code)]

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::vex_e2e_common::{
    assert_absent, assert_attested, assert_not_attested, binary, run_vex, statements_for,
    strip_ledgers, strip_manifest, Marker, PatchApi, VexOutcome, VexRun,
};

/// The classic release the suites install when [`VERSION_ENV`] is unset —
/// the last yarn 1.x, and what the CI runners' corepack provisions.
pub const DEFAULT_YARN_CLASSIC_VERSION: &str = "1.22.22";

/// Overrides the yarn classic release (`1.x.y`, no `yarn@` prefix).
pub const VERSION_ENV: &str = "SOCKET_PATCH_YARN_CLASSIC_E2E_VERSION";

/// `1` turns every "yarn unavailable / registry unreachable" skip into a
/// failure (shared with the yarn berry suites).
pub const REQUIRED_ENV: &str = "SOCKET_PATCH_YARN_E2E_REQUIRED";

/// The yarn classic release under test.
pub fn yarn_classic_version() -> String {
    let version = std::env::var(VERSION_ENV)
        .ok()
        .map(|v| v.trim().trim_start_matches("yarn@").to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_YARN_CLASSIC_VERSION.to_string());
    assert!(
        version.starts_with("1."),
        "{VERSION_ENV}={version:?} is not a yarn classic (1.x) release"
    );
    version
}

/// The corepack spec (`yarn@1.x.y`) of the release under test.
pub fn yarn_classic() -> String {
    format!("yarn@{}", yarn_classic_version())
}

/// `(minor, patch)` of the release under test.
fn minor_patch(version: &str) -> (u32, u32) {
    let mut parts = version.split('.').skip(1).map(|p| p.parse().unwrap_or(0));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0))
}

/// yarn 1.10.0 introduced the `integrity` lock field; earlier releases pin
/// the tarball by the `#<sha1>` fragment of `resolved` alone and DROP an
/// `integrity` line whenever they re-save the lock.
pub fn writes_integrity(version: &str) -> bool {
    minor_patch(version) >= (10, 0)
}

/// yarn 1.7.0 is the first classic release that installs a lock entry whose
/// `resolved` is a local `file:` tarball (what `vendor` writes). 1.0–1.6
/// exit 0 from `install --frozen-lockfile` having installed NOTHING for such
/// an entry (measured 2026-09-22 against 1.0.2 / 1.3.2 / 1.6.0 on node 24),
/// so the vendored suites assert that limitation there instead of the
/// patched bytes; hosted (`https://` tarball) wiring works on every 1.x.
pub fn installs_file_tarballs(version: &str) -> bool {
    minor_patch(version) >= (7, 0)
}

pub fn yarn_e2e_required() -> bool {
    std::env::var(REQUIRED_ENV).is_ok_and(|v| v == "1")
}

/// Print a SKIP line for `suite` — or panic under [`REQUIRED_ENV`]`=1`.
pub fn skip(suite: &str, why: &str) {
    let msg = format!("SKIP {suite} ({}): {why}", yarn_classic());
    if yarn_e2e_required() {
        panic!("{msg} ({REQUIRED_ENV}=1 forbids skipping)");
    }
    println!("{msg}");
}

/// Whether `corepack yarn@<version>` runs AND reports exactly that release,
/// probed from a neutral temp dir (an ancestor `packageManager` field would
/// make corepack refuse) with the suites' cache isolation applied by
/// `isolate`. On `false` the caller returns after [`skip`].
pub fn require_yarn_classic(suite: &str, isolate: impl Fn(&mut Command)) -> bool {
    let spec = yarn_classic();
    let want = yarn_classic_version();
    let probe = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::new("corepack");
    cmd.args([spec.as_str(), "--version"])
        .current_dir(probe.path())
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    isolate(&mut cmd);
    let got = cmd
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    match got {
        Some(v) if v == want => true,
        Some(v) => {
            // A wrong release is never a skip: the leg would silently test
            // another yarn.
            panic!("{suite}: `corepack {spec} --version` reported {v:?}, expected {want}");
        }
        None => {
            skip(
                suite,
                &format!("`corepack {spec}` unavailable (corepack absent or not fetchable)"),
            );
            false
        }
    }
}

// ── manifest-less VEX ─────────────────────────────────────────────────

/// Which wiring the flow produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wiring {
    Hosted,
    Vendored,
}

impl Wiring {
    fn marker(self) -> Marker {
        match self {
            Wiring::Hosted => Marker::Redirected,
            Wiring::Vendored => Marker::Vendored,
        }
    }

    /// The omission code once the ledger outlives a reverted lock.
    fn unwired(self) -> &'static str {
        match self {
            Wiring::Hosted => "redirect_unwired",
            Wiring::Vendored => "vendor_unwired",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Wiring::Hosted => "hosted",
            Wiring::Vendored => "vendored",
        }
    }
}

/// Re-installs a reverted checkout with the real yarn.
pub type Reinstall<'a> = Box<dyn Fn(&Path) + 'a>;

/// Builds an embedded run from the matrix's standalone online run.
pub type Embedded<'a> = Box<dyn Fn(VexRun) -> VexRun + 'a>;

/// `apply --vex` (the post-install hook shape).
pub fn via_apply<'a>() -> Embedded<'a> {
    Box::new(|run| run.via(crate::vex_e2e_common::VexVia::Apply))
}

/// `vendor --vex`.
pub fn via_vendor<'a>() -> Embedded<'a> {
    Box::new(|run| run.via(crate::vex_e2e_common::VexVia::Vendor))
}

/// The manifest-less VEX matrix for one fresh, really-installed checkout.
pub struct ManifestlessVex<'a> {
    /// Suite/leg label for the `VEXCELL` result lines.
    pub leg: &'a str,
    pub wiring: Wiring,
    pub purl: &'a str,
    pub uuid: &'a str,
    /// Exactly the `(vulnerability id, CVE aliases)` the record carries.
    /// Empty = a live production record whose advisory list is not pinned:
    /// every statement for `purl` must then carry the marker, and there must
    /// be at least one.
    pub vulns: &'a [(&'a str, &'a [&'a str])],
    /// Serves the patch view for `uuid` (the record source once the
    /// manifest and ledgers are gone), and is the `--proxy-url` of the
    /// `--offline` cell, whose zero-request claim it checks.
    pub api: &'a PatchApi,
    /// The online runs' `--proxy-url` when it is not [`Self::api`] (the
    /// production suites: the real public patch proxy). The
    /// "record came from the API" request count is then not checked.
    pub proxy_override: Option<String>,
    /// Origin of a hosted lock reference that is not Socket's public patch
    /// server (the flows' wiremock host) — `--patch-server-url`.
    pub patch_server_url: Option<String>,
    /// `yarn.lock` as it reads once the Socket rewrite is reverted (the
    /// registry resolution).
    pub registry_lock: Vec<u8>,
    /// Re-install the reverted lock with the REAL yarn (and assert the
    /// pristine bytes landed), so the reverted cell sees a real tree.
    pub reinstall: Option<Reinstall<'a>>,
    /// Embedded runs (`apply --vex`, `vendor --vex`, `scan … --vex`) that
    /// must attest in the manifest-deleted and ledgers-deleted states: each
    /// maps [`Self::online`] to the run (`.via(..)`, extra args, ...).
    pub embedded: Vec<(&'a str, Embedded<'a>)>,
}

/// Print one result line (`--nocapture` shows them; the matrix script
/// greps them into the per-version table).
fn cell(m: &ManifestlessVex<'_>, name: &str) {
    println!(
        "VEXCELL leg={} yarn={} mode={} cell={name} PASS",
        m.leg,
        yarn_classic_version(),
        m.wiring.label()
    );
}

impl<'a> ManifestlessVex<'a> {
    /// A standalone online run: records come from [`Self::api`] (public
    /// proxy route), hosted references on [`Self::patch_server_url`] count.
    pub fn online(&self) -> VexRun {
        let mut run = VexRun {
            patch_server_url: self.patch_server_url.clone(),
            ..VexRun::online(self.api)
        };
        if let Some(proxy) = &self.proxy_override {
            run.proxy_url = Some(proxy.clone());
        }
        run
    }

    fn attested(&self, out: &VexOutcome, what: &str) {
        assert_eq!(out.code, Some(0), "{}: {what}:\n{out}", self.leg);
        if !self.vulns.is_empty() {
            assert_attested(
                out.doc(),
                self.purl,
                self.uuid,
                self.wiring.marker(),
                self.vulns,
            );
            return;
        }
        let statements = statements_for(out.doc(), self.purl);
        assert!(
            !statements.is_empty(),
            "{}: {what}: no statement for {}:\n{out}",
            self.leg,
            self.purl
        );
        let marker = match self.wiring {
            Wiring::Hosted => "redirected",
            Wiring::Vendored => "vendored",
        };
        let part = format!("Patched via Socket patch {} ({marker})", self.uuid);
        for st in statements {
            assert_eq!(st["status"], "not_affected", "{}: {what}: {st:#}", self.leg);
            let impact = st["impact_statement"].as_str().unwrap_or_default();
            // The expected clause embeds the patch uuid: name it, never print
            // it (CodeQL rust/cleartext-logging).
            assert!(
                impact.split("; ").any(|p| p == part),
                "{}: {what}: impact {impact:?} lacks the wired patch's ({marker}) clause",
                self.leg
            );
        }
    }

    /// Run every embedded command; each must attest. A command may rewrite
    /// the lock or a ledger (`scan --mode hosted` re-resolves), so the
    /// lock is restored and `ledgers` re-applied afterwards: the next cell
    /// must see exactly the state it names.
    fn embedded_attest(&self, project: &Path, state: &str, keep_ledgers: bool) {
        let lock = std::fs::read(project.join("yarn.lock")).expect("yarn.lock");
        for (label, make) in &self.embedded {
            let out = run_vex(&binary(), project, &make(self.online()));
            self.attested(&out, &format!("embedded {label} ({state})"));
            assert!(
                !project.join(".socket/manifest.json").exists(),
                "{}: embedded {label} ({state}) must not write a manifest",
                self.leg
            );
            cell(self, &format!("{state}+{}", label.replace(' ', "_")));
            std::fs::write(project.join("yarn.lock"), &lock).unwrap();
            if !keep_ledgers {
                strip_ledgers(project);
            }
        }
    }

    /// Run every cell over `project` — a fresh checkout the real yarn has
    /// installed from the committed state. Leaves the project reverted.
    ///
    /// 1. `manifest-deleted`: no `.socket/manifest.json` → attested with the
    ///    flow's marker and vuln ids (standalone + every embedded run).
    /// 2. `ledgers-deleted`: no `state.json` / `redirect-state.json` either →
    ///    still attested, from lockfile discovery + a patch-view fetch.
    /// 3. `offline`: same state, `--offline` → `record_unavailable`, exit 1,
    ///    ZERO patch-API requests.
    /// 4. `reverted`: ledgers (and artifacts) back, `yarn.lock` reverted to
    ///    the registry (and really re-installed) → NOT attested
    ///    (`redirect_unwired` / `vendor_unwired`), with and without
    ///    `--no-verify`.
    pub fn run(&self, project: &Path) {
        let leg = self.leg;

        // 1. manifest deleted.
        strip_manifest(project);
        let out = run_vex(&binary(), project, &self.online());
        self.attested(&out, "manifest deleted");
        assert!(
            !project.join(".socket/manifest.json").exists(),
            "{leg}: vex must never write the manifest"
        );
        cell(self, "manifest-deleted");
        self.embedded_attest(project, "manifest-deleted", true);

        // 2. ledgers deleted too: lockfile discovery + the patch API.
        let ledgers = [
            socket_patch_core::vendor::VENDOR_STATE_REL,
            socket_patch_core::patch::redirect::REDIRECT_STATE_REL,
        ]
        .map(|rel| (rel, std::fs::read(project.join(rel)).ok()));
        strip_ledgers(project);
        let before = self.api.view_requests(self.uuid);
        let out = run_vex(&binary(), project, &self.online());
        self.attested(&out, "ledgers deleted");
        assert!(
            self.proxy_override.is_some() || self.api.view_requests(self.uuid) > before,
            "{leg}: with no manifest and no ledger the record must come from the patch API \
             (requests {:?})",
            self.api.requests()
        );
        cell(self, "ledgers-deleted");
        self.embedded_attest(project, "ledgers-deleted", false);

        // 3. offline, no ledgers: the wiring is found, no record → omitted,
        //    and the API is never contacted.
        let before = self.api.request_count();
        let offline = VexRun {
            offline: true,
            proxy_url: Some(self.api.uri()),
            ..self.online()
        };
        let out = run_vex(&binary(), project, &offline);
        assert_eq!(out.code, Some(1), "{leg}: offline:\n{out}");
        assert_not_attested(&out.envelope, self.purl, "record_unavailable");
        assert_absent(out.doc.as_ref(), self.purl);
        assert_eq!(
            self.api.request_count(),
            before,
            "{leg}: --offline made patch-API requests: {:?}",
            self.api.requests()
        );
        cell(self, "offline");

        // 4. lockfile reverted to the registry; ledgers + artifacts kept.
        for (rel, bytes) in &ledgers {
            if let Some(bytes) = bytes {
                std::fs::write(project.join(rel), bytes).unwrap();
            }
        }
        std::fs::write(project.join("yarn.lock"), &self.registry_lock).unwrap();
        if let Some(reinstall) = &self.reinstall {
            reinstall(project);
        }
        let had_ledger = ledgers.iter().any(|(_, b)| b.is_some());
        for no_verify in [false, true] {
            let run = VexRun {
                no_verify,
                ..self.online()
            };
            let out = run_vex(&binary(), project, &run);
            assert_absent(out.doc.as_ref(), self.purl);
            if had_ledger {
                assert_eq!(
                    out.code,
                    Some(1),
                    "{leg}: reverted (no_verify={no_verify}):\n{out}"
                );
                assert_not_attested(&out.envelope, self.purl, self.wiring.unwired());
            } else {
                // No ledger and no wiring: nothing left to even consider.
                assert_ne!(
                    out.code,
                    Some(0),
                    "{leg}: reverted (no_verify={no_verify}):\n{out}"
                );
            }
            cell(
                self,
                if no_verify {
                    "reverted+no-verify"
                } else {
                    "reverted"
                },
            );
        }
    }
}

/// `(key, value)` env pairs as [`VexRun::envs`] wants them.
pub fn envs(pairs: &[(&str, &str)]) -> Vec<(String, OsString)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), OsString::from(v)))
        .collect()
}
