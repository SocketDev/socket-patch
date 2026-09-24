//! Shared pieces of the REAL-yarn-berry e2e suites: which yarn release they
//! drive, and the manifest-less VEX matrix every hosted / vendored berry
//! flow ends with.
//!
//! Pull it in AFTER the VEX helper (this module uses it):
//!
//! ```ignore
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! #[path = "yarn_berry_common/mod.rs"]
//! mod yarn_berry_common;
//! use yarn_berry_common::*;
//! ```
//!
//! # Which yarn
//!
//! Socket's hosted redirect and vendored wiring support yarn berry only at
//! cacheKey `10c0` (yarn 4, `compressionLevel: 0` — the default), the one
//! cache-zip checksum recipe that reproduces offline. The node-modules /
//! pnpm-linker / workspaces suites therefore run yarn **4**: the release is
//! [`DEFAULT_YARN_BERRY`] unless [`VERSION_ENV`] names another 4.x release
//! (`SOCKET_PATCH_YARN_BERRY_VERSION=4.0.2 cargo test …` — how a CI matrix
//! leg or a local loop pins each release). yarn 2 and 3 (cacheKeys 7/8) are
//! REFUSED by both modes; `e2e_yarn_legacy_cachekey_refusal_build.rs` pins
//! that refusal (and that VEX then attests nothing) against the real final
//! releases of those majors.
//!
//! [`REQUIRED_ENV`]`=1` turns every "toolchain unavailable / registry
//! unreachable" soft-skip into a failure, for a CI leg that provisioned
//! corepack on purpose.
//!
//! # The manifest-less VEX matrix ([`run_manifestless_vex_matrix`])
//!
//! A hosted (`scan --mode hosted`) or vendored (`vendor`, `get --mode
//! vendored`, a depscan-opened PR) berry checkout may carry no
//! `.socket/manifest.json` — and often no ledgers either. After a flow has
//! produced its committed state, the matrix proves `socket-patch vex`
//! attests (and refuses to attest) from what such a checkout carries,
//! against a FRESH copy installed by the REAL yarn:
//!
//! | cell | shape | expectation |
//! |---|---|---|
//! | `manifest-deleted` | ledgers + artifacts, `--immutable --check-cache` install | online + offline attest (ledger record); embedded `apply --vex` (+ `vendor --vex` / `scan --mode hosted --vex`) attest |
//! | `ledgers-deleted` | lockfile (+ vendored artifact) only | online attests from the API record; embedded `apply --vex` attests |
//! | `offline` | no ledgers, `--offline` | `record_unavailable`, exit 1, ZERO API requests |
//! | `tampered` | installed file (hosted) / artifact member (vendored) altered | `hash_mismatch` / `vendor_hash_mismatch` |
//! | `reverted` | lock (+ package.json) back to the registry, ledgers + artifacts kept, real `--immutable` install of the pristine bytes | `redirect_unwired` / `vendor_unwired` with AND without `--no-verify`, online and offline, zero API requests; with the ledgers gone too: nothing discovered |
//! | `reverted-lock-only` (vendored) | lock reverted, the `resolutions` mapping left behind | `vendor_unwired` (with and without `--no-verify`) |
//! | `pnp-linker` | the SAME wired lock installed under `nodeLinker: pnp` | the documented PnP contract: standalone vex attests from the lock's `checksum:` pin (hosted) / the committed artifact (vendored); `apply --vex` refuses (`yarn_pnp_unsupported`) |
//!
//! Every cell prints one `VEX-MATRIX|<yarn>|<flow>|<mode>|<cell>|PASS` line
//! (visible with `--nocapture`), which is how the per-version results table
//! is collected.

#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::OnceLock;

use crate::vex_e2e_common::{
    assert_absent, assert_attested, binary, git_sha256, patch_view, run_vex, strip_ledgers,
    strip_manifest, Marker, PatchApi, VexOutcome, VexRun, VexVia,
};

/// The yarn 4 release the berry suites drive when [`VERSION_ENV`] is unset.
pub const DEFAULT_YARN_BERRY: &str = "4.12.0";

/// Selects the yarn 4 release (`4.0.2`, `4.6.0`, … — bare, or as `yarn@X`).
pub const VERSION_ENV: &str = "SOCKET_PATCH_YARN_BERRY_VERSION";

/// `=1`: a toolchain / registry soft-skip is a FAILURE instead.
pub const REQUIRED_ENV: &str = "SOCKET_PATCH_YARN_E2E_REQUIRED";

/// Whether [`REQUIRED_ENV`] forbids soft-skips.
pub fn yarn_e2e_required() -> bool {
    std::env::var(REQUIRED_ENV).is_ok_and(|v| v == "1")
}

/// The corepack spec (`yarn@<X>`) of the yarn 4 release under test.
///
/// Panics on a non-4.x [`VERSION_ENV`]: these suites prove the SUPPORTED
/// flow, and a 2.x/3.x lock is refused by design (the legacy refusal suite
/// covers those majors) — silently "passing" a refused major here would be
/// a vacuous green.
pub fn yarn_berry() -> &'static str {
    static SPEC: OnceLock<String> = OnceLock::new();
    SPEC.get_or_init(|| {
        let raw = std::env::var(VERSION_ENV)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_YARN_BERRY.to_string());
        let version = raw.strip_prefix("yarn@").unwrap_or(&raw).to_string();
        let parts: Vec<&str> = version.split('.').collect();
        let numeric = parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        assert!(
            numeric && parts[0] == "4",
            "{VERSION_ENV}={raw:?}: the hosted/vendored berry suites need an exact yarn \
             4.x release (cacheKey 10c0 is the only supported berry cache). yarn 2/3 are \
             refused by both modes — see e2e_yarn_legacy_cachekey_refusal_build.rs."
        );
        format!("yarn@{version}")
    })
    .as_str()
}

/// Pin the yarn berry defaults that depend on whether yarn thinks it is
/// running under CI. Apply it after the `YARN_*` scrub and `cache_env::isolate`,
/// and before the call site's own env.
///
/// yarn 3+ turns `enableImmutableInstalls` on by default when it detects CI
/// (ci-info: `CI`, `GITHUB_ACTIONS`, …). Under that default, the plain
/// `yarn install` that creates each fixture's lockfile fails with YN0028 ("The
/// lockfile would have been created by this install, which is explicitly
/// forbidden"), exit 1 and nothing on stderr. That broke every hosted,
/// vendored, pnpm-linker, workspaces and yarn 3 refusal fixture on the
/// ubuntu/macOS yarn-berry legs. yarn 2 keeps the default off, which is why
/// its refusal legs stayed green. The pin:
///
/// * forces `CI=true`, so a developer's local run gets the same defaults as
///   the CI leg. Without the second pin, every suite fails locally too,
///   instead of only on a runner;
/// * sets `YARN_ENABLE_IMMUTABLE_INSTALLS=false`, so a plain `install` may
///   write the lock. The fresh-checkout installs are unaffected because they
///   pass `--immutable` explicitly, and yarn's flag outranks the setting.
pub fn pin_berry_ci_defaults(cmd: &mut std::process::Command) -> &mut std::process::Command {
    cmd.env("CI", "true")
        .env("YARN_ENABLE_IMMUTABLE_INSTALLS", "false")
}

/// [`pin_berry_ci_defaults`] wins over an earlier value for either variable
/// (`get_envs` reports the last value set for each key).
#[test]
fn pin_berry_ci_defaults_sets_ci_and_disables_implicit_immutable() {
    let mut cmd = std::process::Command::new("corepack");
    cmd.env("YARN_ENABLE_IMMUTABLE_INSTALLS", "true");
    pin_berry_ci_defaults(&mut cmd);
    let envs: std::collections::HashMap<_, _> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_os_string(), v.map(|v| v.to_os_string())))
        .collect();
    assert_eq!(
        envs.get(std::ffi::OsStr::new("CI")),
        Some(&Some("true".into()))
    );
    assert_eq!(
        envs.get(std::ffi::OsStr::new("YARN_ENABLE_IMMUTABLE_INSTALLS")),
        Some(&Some("false".into()))
    );
}

/// The cache-zip checksum a real yarn wrote into `lock` (the first entry
/// `checksum:`), normalized to the prefixed `10c0/<hex>` the patch API's
/// `yarnBerry10c0` carries. yarn 4.0.x writes the BARE hex under cacheKey
/// `10c0`; 4.1+ writes `10c0/<hex>` — both name the same digest. `None`
/// when the lock carries no 128-hex `10c0` checksum.
pub fn yarn_written_checksum(lock: &str) -> Option<String> {
    lock.lines().find_map(|l| {
        let value = l.strip_prefix("  checksum: ")?.trim();
        let hex = value.strip_prefix("10c0/").unwrap_or(value);
        (hex.len() == 128 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| format!("10c0/{hex}"))
    })
}

/// The `checksum:` line a Socket-written entry must carry in a lock whose
/// real-yarn spelling was `yarn_lock` (see [`yarn_written_checksum`]): the
/// bare hex for a yarn 4.0.x lock, `10c0/<hex>` otherwise — `--immutable`
/// rejects a respelled checksum (YN0028).
pub fn expected_checksum_line(yarn_lock: &str, checksum_10c0: &str) -> String {
    let bare = yarn_lock
        .lines()
        .filter_map(|l| l.strip_prefix("  checksum: "))
        .any(|v| !v.contains('/'));
    let hex = checksum_10c0.strip_prefix("10c0/").unwrap_or(checksum_10c0);
    if bare {
        format!("  checksum: {hex}")
    } else {
        format!("  checksum: 10c0/{hex}")
    }
}

/// Run `f` on a fresh OS thread and return its result (re-raising a panic)./// Run `f` on a fresh OS thread and return its result (re-raising a panic).
///
/// [`PatchApi`] owns its own tokio runtime; creating, blocking on or
/// dropping one from inside a `#[tokio::test]` body panics ("Cannot start
/// a runtime from within a runtime"). The async capstones run the matrix
/// through this so it sees no ambient runtime, while the test's own
/// wiremock server (serving the hosted tarball) keeps running on the
/// test runtime's worker threads.
pub fn off_runtime<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|s| match s.spawn(f).join() {
        Ok(r) => r,
        Err(panic) => std::panic::resume_unwind(panic),
    })
}

/// How the flow wired the patched dependency.
#[derive(Clone, Debug)]
pub enum BerryWiring {
    /// `yarn.lock` resolves it via `::__archiveUrl=` on `patch_server`
    /// (the mock tarball host — not a Socket host, so every VEX run passes
    /// it as `--patch-server-url`).
    Hosted { patch_server: String },
    /// `yarn.lock` + the root `resolutions` wire it to the committed
    /// `.socket/vendor/npm/<uuid>/<leaf>.tgz` at `artifact_rel`.
    Vendored { artifact_rel: String },
}

impl BerryWiring {
    fn name(&self) -> &'static str {
        match self {
            BerryWiring::Hosted { .. } => "hosted",
            BerryWiring::Vendored { .. } => "vendored",
        }
    }

    fn marker(&self) -> Marker {
        match self {
            BerryWiring::Hosted { .. } => Marker::Redirected,
            BerryWiring::Vendored { .. } => Marker::Vendored,
        }
    }

    fn unwired_reason(&self) -> &'static str {
        match self {
            BerryWiring::Hosted { .. } => "redirect_unwired",
            BerryWiring::Vendored { .. } => "vendor_unwired",
        }
    }

    fn patch_server(&self) -> Option<String> {
        match self {
            BerryWiring::Hosted { patch_server } => Some(patch_server.clone()),
            BerryWiring::Vendored { .. } => None,
        }
    }
}

/// The flow's own mocked patch API, for re-running its embedded command
/// (`scan --mode hosted --vex`) on the manifest-less checkout.
#[derive(Clone, Debug)]
pub struct FlowApi {
    pub api_url: String,
    pub org: String,
}

/// Runs `corepack <yarn> <args>` in a dir with the suite's hermetic env plus
/// the given extra variables. Each suite passes a closure over its own
/// `corepack` helper (which owns the `YARN_*`/`SOCKET_*` scrub + cache
/// isolation).
pub type YarnRunner<'a> = &'a (dyn Fn(&Path, &[&str], &[(&str, &str)]) -> Output + Sync);

/// One berry flow's committed state, handed to [`run_manifestless_vex_matrix`].
pub struct BerryVexFlow<'a> {
    /// Short flow name (`node-modules`, `pnpm-linker`, `workspaces`, …).
    pub flow: &'a str,
    /// The corepack spec the flow's [`Self::yarn`] runs (`yarn@4.12.0`) —
    /// normally [`yarn_berry`]; a suite pinned to one release passes its own.
    pub yarn_spec: &'a str,
    pub wiring: BerryWiring,
    /// The flow's project AFTER it wired the patch (it may still hold a
    /// manifest; the matrix never mutates it).
    pub proj: &'a Path,
    /// Scratch dir the fresh checkouts are created under.
    pub scratch: &'a Path,
    /// The committable files besides `.socket/` (relative to `proj`):
    /// `package.json`, `yarn.lock`, workspace member manifests, …
    pub committable: &'a [&'a str],
    /// `.yarnrc.yml` of a fresh checkout (hosted: whitelist the mock host
    /// for http and poison `npmRegistryServer`).
    pub yarnrc: &'a str,
    /// `(relative path, bytes)` of every committable file BEFORE the flow
    /// wired the patch — at least `yarn.lock` (and, vendored, the root
    /// `package.json` whose `resolutions` the flow added).
    pub registry_state: &'a [(&'a str, Vec<u8>)],
    pub purl: &'a str,
    pub uuid: &'a str,
    /// `(vulnerability id, CVE aliases)` the patch record carries.
    pub vulns: &'a [(&'a str, &'a [&'a str])],
    /// The patched `package/index.js` bytes.
    pub patched: &'a [u8],
    /// The pristine (registry) `package/index.js` bytes.
    pub pristine: &'a [u8],
    /// Where a node-modules/pnpm-linker install exposes the patched file
    /// (`node_modules/left-pad/index.js`).
    pub installed: &'a str,
    /// The flow's yarn project cache (`<proj>/.yarn/cache`, holding the
    /// registry zip) — seeds the reverted checkout's offline install.
    pub registry_cache: PathBuf,
    /// Runs the flow's yarn (see [`YarnRunner`]).
    pub yarn: YarnRunner<'a>,
    /// Re-run the flow's `scan --mode hosted --vex` embedded (hosted flows).
    pub flow_api: Option<FlowApi>,
    /// Run the `pnp-linker` cell: the same wired lock installed with the
    /// yarnrc's `nodeLinker` switched to `pnp`.
    pub pnp_cell: bool,
}

/// Record key of the patched file in the patch record.
const RECORD_FILE: &str = "package/index.js";

impl<'a> BerryVexFlow<'a> {
    fn cell_tag(&self, cell: &str) -> String {
        format!(
            "{}|{}|{}|{cell}",
            self.yarn_spec,
            self.flow,
            self.wiring.name()
        )
    }

    fn pass(&self, cell: &str) {
        println!("VEX-MATRIX|{}|PASS", self.cell_tag(cell));
        let _ = std::io::stdout().flush();
    }

    /// A standalone online run against `api` (public-proxy route; hosted
    /// references on the mock tarball host count).
    fn online(&self, api: &PatchApi) -> VexRun {
        VexRun {
            patch_server_url: self.wiring.patch_server(),
            ..VexRun::online(api)
        }
    }

    /// A standalone `--offline` run (the proxy is still configured so a
    /// stray request would be COUNTED rather than fail to resolve).
    fn offline(&self, api: &PatchApi) -> VexRun {
        VexRun {
            offline: true,
            ..self.online(api)
        }
    }

    /// Copy the committable files + `.socket/` (per `socket`) into
    /// `<scratch>/<name>` with the fresh yarnrc. Returns the new dir.
    fn checkout(&self, name: &str, socket: bool) -> PathBuf {
        let fresh = self.scratch.join(name);
        assert!(!fresh.exists(), "{name}: scratch dir reused");
        for rel in self.committable {
            let to = fresh.join(rel);
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(self.proj.join(rel), &to)
                .unwrap_or_else(|e| panic!("{name}: copying {rel}: {e}"));
        }
        std::fs::write(fresh.join(".yarnrc.yml"), self.yarnrc).unwrap();
        if socket && self.proj.join(".socket").is_dir() {
            copy_dir(&self.proj.join(".socket"), &fresh.join(".socket"));
        }
        fresh
    }

    /// `yarn install <args>` in `dir` with a private, empty global folder.
    fn install(&self, dir: &Path, args: &[&str], ctx: &str) {
        let global = self.scratch.join(format!(
            "{}-yarn-global",
            dir.file_name().unwrap().to_string_lossy()
        ));
        let out = (self.yarn)(
            dir,
            args,
            &[
                ("YARN_GLOBAL_FOLDER", global.to_str().unwrap()),
                ("YARN_ENABLE_GLOBAL_CACHE", "false"),
            ],
        );
        assert!(
            out.status.success(),
            "{ctx}: `{} {}` failed.\nstdout:\n{}\nstderr:\n{}",
            self.yarn_spec,
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    fn installed_bytes(&self, dir: &Path) -> Vec<u8> {
        std::fs::read(dir.join(self.installed))
            .unwrap_or_else(|e| panic!("{}: {e}", dir.join(self.installed).display()))
    }

    fn assert_attested_run(&self, out: &VexOutcome, ctx: &str) {
        assert_eq!(out.code, Some(0), "{ctx}: {out}");
        assert_attested(
            out.doc(),
            self.purl,
            self.uuid,
            self.wiring.marker(),
            self.vulns,
        );
        if out.envelope.get("events").is_some() {
            let verified = out.envelope["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| e["action"] == "verified" && e["purl"] == self.purl)
                .count();
            assert_eq!(verified, 1, "{ctx}: one verified event: {out}");
        }
    }

    fn assert_omitted_run(&self, out: &VexOutcome, reason: &str, ctx: &str) {
        crate::vex_e2e_common::assert_omitted(out, self.purl, reason, ctx);
    }
}

/// Recursive copy (files and dirs; symlinks are followed).
pub fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// A single-member `.tgz` whose `package/index.js` holds `bytes` — the
/// tampered stand-in for a committed vendored artifact.
fn single_member_tgz(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::new(6));
        let mut builder = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, RECORD_FILE, bytes)
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }
    out
}

/// Run the manifest-less VEX matrix (module docs) over a flow's committed
/// state. Every assertion is hard; returns the cells that passed.
pub fn run_manifestless_vex_matrix(flow: &BerryVexFlow<'_>) -> Vec<String> {
    let mut passed = Vec::new();
    let mut pass = |cell: &str| {
        flow.pass(cell);
        passed.push(cell.to_string());
    };
    let api = PatchApi::start(vec![(
        flow.uuid.to_string(),
        patch_view(
            flow.uuid,
            flow.purl,
            &[(RECORD_FILE, &git_sha256(flow.patched))],
            flow.vulns,
        ),
    )]);
    let bin = binary();
    let unwired = flow.wiring.unwired_reason();
    let is_hosted = matches!(flow.wiring, BerryWiring::Hosted { .. });

    // ── manifest-deleted: ledgers + artifacts travel, the real yarn installs ──
    let fresh = flow.checkout("vex-manifest-deleted", true);
    strip_manifest(&fresh);
    assert!(
        fresh.join(".socket/vendor").is_dir(),
        "manifest-deleted: the flow must have left its .socket/vendor ledgers"
    );
    flow.install(
        &fresh,
        &["install", "--immutable", "--check-cache"],
        "manifest-deleted install",
    );
    assert_eq!(
        flow.installed_bytes(&fresh),
        flow.patched,
        "manifest-deleted: the real yarn must install the PATCHED bytes"
    );

    let ctx = flow.cell_tag("manifest-deleted/online");
    let out = run_vex(&bin, &fresh, &flow.online(&api));
    flow.assert_attested_run(&out, &ctx);
    assert!(
        !fresh.join(".socket/manifest.json").exists(),
        "{ctx}: vex never writes the manifest"
    );
    pass("manifest-deleted/online");

    let before = api.request_count();
    let ctx = flow.cell_tag("manifest-deleted/offline-ledger");
    let out = run_vex(&bin, &fresh, &flow.offline(&api));
    flow.assert_attested_run(&out, &ctx);
    assert_eq!(
        api.request_count(),
        before,
        "{ctx}: --offline made a request"
    );
    pass("manifest-deleted/offline-ledger");

    let ctx = flow.cell_tag("manifest-deleted/apply--vex");
    let out = run_vex(&bin, &fresh, &flow.online(&api).via(VexVia::Apply));
    assert_eq!(out.code, Some(0), "{ctx}: {out}");
    assert_eq!(out.envelope["status"], "noManifest", "{ctx}: {out}");
    assert!(
        out.envelope["vex"]["statements"].as_u64() >= Some(1),
        "{ctx}: {out}"
    );
    assert_attested(
        out.doc(),
        flow.purl,
        flow.uuid,
        flow.wiring.marker(),
        flow.vulns,
    );
    assert_eq!(
        flow.installed_bytes(&fresh),
        flow.patched,
        "{ctx}: apply must leave the installed tree alone"
    );
    pass("manifest-deleted/apply--vex");

    if !is_hosted {
        let ctx = flow.cell_tag("manifest-deleted/vendor--vex");
        let lock_before = std::fs::read(fresh.join("yarn.lock")).unwrap();
        let out = run_vex(&bin, &fresh, &flow.online(&api).via(VexVia::Vendor));
        assert_eq!(out.code, Some(0), "{ctx}: {out}");
        assert_eq!(out.envelope["status"], "noManifest", "{ctx}: {out}");
        assert_attested(
            out.doc(),
            flow.purl,
            flow.uuid,
            flow.wiring.marker(),
            flow.vulns,
        );
        assert_eq!(
            std::fs::read(fresh.join("yarn.lock")).unwrap(),
            lock_before,
            "{ctx}: the wiring is left untouched"
        );
        pass("manifest-deleted/vendor--vex");
    }

    if let Some(flow_api) = &flow.flow_api {
        // The flow's own command, re-run on the manifest-less checkout: the
        // lock is already redirected, so it is a no-op rewrite whose in-run
        // VEX still attests the wired patch.
        let ctx = flow.cell_tag("manifest-deleted/scan--mode-hosted--vex");
        let lock_before = std::fs::read(fresh.join("yarn.lock")).unwrap();
        let run = VexRun {
            api_url: Some(flow_api.api_url.clone()),
            org: Some(flow_api.org.clone()),
            api_token: Some("fake".to_string()),
            patch_server_url: flow.wiring.patch_server(),
            ..VexRun::default()
        }
        .via(VexVia::Scan)
        .arg("--mode")
        .arg("hosted")
        .arg("--yes");
        let out = run_vex(&bin, &fresh, &run);
        assert_eq!(out.code, Some(0), "{ctx}: {out}");
        assert!(
            out.envelope["vex"]["statements"].as_u64() >= Some(1),
            "{ctx}: {out}"
        );
        assert_attested(
            out.doc(),
            flow.purl,
            flow.uuid,
            flow.wiring.marker(),
            flow.vulns,
        );
        assert_eq!(
            std::fs::read(fresh.join("yarn.lock")).unwrap(),
            lock_before,
            "{ctx}: an already-redirected lock is left byte-identical"
        );
        assert!(!fresh.join(".socket/manifest.json").exists(), "{ctx}");
        pass("manifest-deleted/scan--mode-hosted--vex");
    }

    // ── ledgers-deleted: the lockfile (+ artifact) is the only evidence ──
    strip_ledgers(&fresh);
    if let BerryWiring::Vendored { artifact_rel } = &flow.wiring {
        assert!(
            fresh.join(artifact_rel).is_file(),
            "ledgers-deleted: the committed artifact stays"
        );
    }
    let views_before = api.view_requests(flow.uuid);
    let ctx = flow.cell_tag("ledgers-deleted/online");
    let out = run_vex(&bin, &fresh, &flow.online(&api));
    flow.assert_attested_run(&out, &ctx);
    assert!(
        api.view_requests(flow.uuid) > views_before,
        "{ctx}: the record must come from the patch API"
    );
    pass("ledgers-deleted/online");

    let ctx = flow.cell_tag("ledgers-deleted/apply--vex");
    let out = run_vex(&bin, &fresh, &flow.online(&api).via(VexVia::Apply));
    assert_eq!(out.code, Some(0), "{ctx}: {out}");
    assert_eq!(out.envelope["status"], "noManifest", "{ctx}: {out}");
    assert_attested(
        out.doc(),
        flow.purl,
        flow.uuid,
        flow.wiring.marker(),
        flow.vulns,
    );
    pass("ledgers-deleted/apply--vex");

    // ── offline, no ledgers: no record anywhere, zero network ──
    let before = api.request_count();
    let ctx = flow.cell_tag("offline");
    let out = run_vex(&bin, &fresh, &flow.offline(&api));
    flow.assert_omitted_run(&out, "record_unavailable", &ctx);
    assert_eq!(
        api.request_count(),
        before,
        "{ctx}: --offline made a request"
    );
    let out = run_vex(&bin, &fresh, &flow.offline(&api).via(VexVia::Apply));
    assert_eq!(out.code, Some(1), "{ctx} apply --vex: {out}");
    assert_eq!(
        out.envelope["error"]["code"], "no_applicable_patches",
        "{ctx} apply --vex: {out}"
    );
    assert_absent(out.doc.as_ref(), flow.purl);
    assert!(out.doc.is_none(), "{ctx} apply --vex: no document");
    assert_eq!(
        api.request_count(),
        before,
        "{ctx}: --offline made a request"
    );
    pass("offline");

    // ── tampered: the evidence no longer hashes to the record ──
    let ctx = flow.cell_tag("tampered");
    match &flow.wiring {
        BerryWiring::Hosted { .. } => {
            let path = fresh.join(flow.installed);
            let honest = std::fs::read(&path).unwrap();
            // Through the pnpm-linker symlink too: write the target file.
            std::fs::write(&path, b"/* tampered after install */\n").unwrap();
            let out = run_vex(&bin, &fresh, &flow.online(&api));
            flow.assert_omitted_run(&out, "hash_mismatch", &ctx);
            std::fs::write(&path, honest).unwrap();
        }
        BerryWiring::Vendored { artifact_rel } => {
            let path = fresh.join(artifact_rel);
            let honest = std::fs::read(&path).unwrap();
            std::fs::write(&path, single_member_tgz(b"/* tampered artifact */\n")).unwrap();
            let out = run_vex(&bin, &fresh, &flow.online(&api));
            flow.assert_omitted_run(&out, "vendor_hash_mismatch", &ctx);
            std::fs::write(&path, honest).unwrap();
        }
    }
    let out = run_vex(&bin, &fresh, &flow.online(&api));
    flow.assert_attested_run(&out, &format!("{ctx} (restored)"));
    pass("tampered");

    // ── reverted: lock (+ package.json) back to the registry; ledgers and
    //    artifacts stay; the real yarn installs the PRISTINE bytes ──
    let reverted = flow.checkout("vex-reverted", true);
    strip_manifest(&reverted);
    for (rel, bytes) in flow.registry_state {
        std::fs::write(reverted.join(rel), bytes).unwrap();
    }
    if flow.registry_cache.is_dir() {
        copy_dir(&flow.registry_cache, &reverted.join(".yarn/cache"));
    }
    flow.install(&reverted, &["install", "--immutable"], "reverted install");
    assert_eq!(
        flow.installed_bytes(&reverted),
        flow.pristine,
        "reverted: the real yarn must install the registry bytes"
    );
    let before = api.request_count();
    for (label, base) in [
        ("offline", flow.offline(&api)),
        ("online", flow.online(&api)),
    ] {
        for no_verify in [false, true] {
            let ctx = flow.cell_tag(&format!("reverted/{label}/no-verify={no_verify}"));
            let run = VexRun {
                no_verify,
                ..base.clone()
            };
            let out = run_vex(&bin, &reverted, &run);
            flow.assert_omitted_run(&out, unwired, &ctx);
        }
    }
    assert_eq!(
        api.request_count(),
        before,
        "reverted: a stale ledger must never send vex to the API"
    );
    // Even a leftover PATCHED install cannot revive the stale ledger — the
    // wiring, not the tree, decides (the next install replaces it anyway).
    std::fs::write(reverted.join(flow.installed), flow.patched).unwrap();
    let ctx = flow.cell_tag("reverted/stale-patched-tree");
    let out = run_vex(&bin, &reverted, &flow.offline(&api));
    flow.assert_omitted_run(&out, unwired, &ctx);
    std::fs::write(reverted.join(flow.installed), flow.pristine).unwrap();
    let ctx = flow.cell_tag("reverted/apply--vex");
    let out = run_vex(&bin, &reverted, &flow.offline(&api).via(VexVia::Apply));
    assert_ne!(
        out.code,
        Some(0),
        "{ctx}: a stale ledger fails the requested VEX: {out}"
    );
    assert!(out.doc.is_none(), "{ctx}: no document: {out}");
    strip_ledgers(&reverted);
    let ctx = flow.cell_tag("reverted/no-ledgers");
    let out = run_vex(&bin, &reverted, &flow.online(&api));
    assert_eq!(out.code, Some(2), "{ctx}: {out}");
    assert_eq!(
        out.envelope["error"]["code"], "manifest_not_found",
        "{ctx}: nothing is discovered: {out}"
    );
    assert!(out.doc.is_none(), "{ctx}");
    assert_eq!(api.request_count(), before, "{ctx}: nothing to fetch");
    pass("reverted");

    // ── reverted-lock-only (vendored): the `resolutions` mapping survives
    //    but the lock no longer carries the `file:` entry ──
    if !is_hosted {
        let half = flow.checkout("vex-reverted-lock-only", true);
        strip_manifest(&half);
        let lock = flow
            .registry_state
            .iter()
            .find(|(rel, _)| *rel == "yarn.lock")
            .expect("registry_state carries yarn.lock");
        std::fs::write(half.join("yarn.lock"), &lock.1).unwrap();
        for no_verify in [false, true] {
            let ctx = flow.cell_tag(&format!("reverted-lock-only/no-verify={no_verify}"));
            let run = VexRun {
                no_verify,
                ..flow.offline(&api)
            };
            let out = run_vex(&bin, &half, &run);
            flow.assert_omitted_run(&out, unwired, &ctx);
        }
        pass("reverted-lock-only");
    }

    // ── pnp-linker: the documented Plug'n'Play contract on a REAL PnP
    //    install of the same wired lock ──
    if flow.pnp_cell {
        let pnp = flow.checkout("vex-pnp", false);
        let yarnrc = flow
            .yarnrc
            .lines()
            .filter(|l| !l.trim_start().starts_with("nodeLinker:"))
            .chain(std::iter::once("nodeLinker: pnp"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(pnp.join(".yarnrc.yml"), format!("{yarnrc}\n")).unwrap();
        if let BerryWiring::Vendored { artifact_rel } = &flow.wiring {
            let to = pnp.join(artifact_rel);
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(flow.proj.join(artifact_rel), &to).unwrap();
        }
        flow.install(
            &pnp,
            &["install", "--immutable", "--check-cache"],
            "pnp install",
        );
        assert!(
            pnp.join(".pnp.cjs").is_file(),
            "pnp-linker: a real PnP install writes .pnp.cjs"
        );
        assert!(
            !pnp.join(flow.installed).exists(),
            "pnp-linker: no node_modules tree under PnP"
        );
        let ctx = flow.cell_tag("pnp-linker/vex");
        let out = run_vex(&bin, &pnp, &flow.online(&api));
        flow.assert_attested_run(&out, &ctx);
        let ctx = flow.cell_tag("pnp-linker/apply--vex");
        // The refusal fires before VEX generation, so (like every apply
        // failure that precedes generation) it does not clean up a previous
        // run's document: start from an empty path to observe THIS run.
        std::fs::remove_file(&out.output).unwrap();
        let out = run_vex(&bin, &pnp, &flow.online(&api).via(VexVia::Apply));
        assert_eq!(out.code, Some(1), "{ctx}: {out}");
        assert_eq!(
            out.envelope["error"]["code"], "yarn_pnp_unsupported",
            "{ctx}: {out}"
        );
        assert!(out.doc.is_none(), "{ctx}: no document");
        pass("pnp-linker");
    }

    passed
}
