//! The real-vlt capstone harness (DESIGN §8.3), shared by
//! `e2e_redirect_vlt_build`, `e2e_vendor_vlt_build`, `mode_migration_vlt`,
//! `e2e_safety_vlt`, `e2e_vlt` and the production suites.
//!
//! Include with `#[path = "vlt_e2e_common/mod.rs"] mod vlt_e2e_common;`.
//!
//! # Gate environment
//!
//! * `SOCKET_PATCH_VLT_E2E_JS`: absolute path to `vlt.js`, run as
//!   `node --no-warnings <js> …`.
//! * `SOCKET_PATCH_VLT_E2E_VERSION`: must equal `--version` exactly.
//! * `SOCKET_PATCH_VLT_E2E_REQUIRED`: non-empty turns a toolchain skip into
//!   a failure. A set `_JS` implies it, and with `CI=true` a leg fails when
//!   `_JS` is unset.
//! * `SOCKET_PATCH_VLT_E2E_SOCKET_BIN`: the socket-patch binary to drive
//!   (for prebuilt test executables whose `CARGO_BIN_EXE_*` path moved).
//! * `SOCKET_PATCH_VLT_E2E_UPGRADE_JS` / `_UPGRADE_VERSION`: a second vlt
//!   for the upgrade legs.
//! * `SOCKET_PATCH_VLT_E2E_STORE_LINKER` ∈ {auto, hardlink, copy, unpack}
//!   and `SOCKET_PATCH_VLT_E2E_CACHE_ROOT`: applied after the ambient
//!   scrub (which drops `VLT_STORE_LINKER` / `VLT_CACHE`).
//!
//! # Counting
//!
//! Every leg prints exactly one `VLT-LEG <version> <os> <suite> <leg>
//! ran|skip:<reason>` line to stderr ([`Leg::ran`] / [`Leg::skip`]); a leg
//! that panics prints none, which `scripts/check-vlt-legs.py` reports as a
//! missing `ran`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "../common/mod.rs"]
pub mod common;
pub mod fixture;

pub use common::cache_env;

// ── versions and eras ─────────────────────────────────────────────────────

/// A vlt release: `0.0.0-N`, `1.0.0-rc.N` or a plain release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VltVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<u64>,
}

impl VltVersion {
    pub const fn release(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: None,
        }
    }

    pub const fn zero(n: u64) -> Self {
        Self {
            major: 0,
            minor: 0,
            patch: 0,
            pre: Some(n),
        }
    }

    pub const fn rc(n: u64) -> Self {
        Self {
            major: 1,
            minor: 0,
            patch: 0,
            pre: Some(n),
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        let (core, pre) = match raw.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (raw, None),
        };
        let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
        let major = parts.next()??;
        let minor = parts.next()??;
        let patch = parts.next()??;
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => None,
            Some(p) => Some(p.strip_prefix("rc.").unwrap_or(p).parse::<u64>().ok()?),
        };
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    fn key(self) -> (u64, u64, u64, bool, u64) {
        (
            self.major,
            self.minor,
            self.patch,
            self.pre.is_none(),
            self.pre.unwrap_or(0),
        )
    }
}

impl PartialOrd for VltVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VltVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

impl std::fmt::Display for VltVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.major, self.pre) {
            (0, Some(n)) => write!(f, "0.0.0-{n}"),
            (_, Some(n)) => write!(f, "{}.{}.{}-rc.{n}", self.major, self.minor, self.patch),
            (_, None) => write!(f, "{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

/// `vlt ci`, `--frozen-lockfile` and `--expect-lockfile` exist.
pub const HAS_CI_FROM: VltVersion = VltVersion::zero(19);
/// A root `postinstall` runs without an `install` script.
pub const ROOT_POSTINSTALL_FROM: VltVersion = VltVersion::rc(13);
/// Install commands need a registry configuration.
pub const NEEDS_REGISTRY_CONFIG_FROM: VltVersion = VltVersion::rc(33);
/// Bare specs honor `registries.npm`.
pub const REGISTRIES_NPM_ROUTES_FROM: VltVersion = VltVersion::rc(33);
/// Releases that skip registry tarball integrity on a cold fetch.
pub const INTEGRITY_UNENFORCED: &[VltVersion] = &[VltVersion::zero(1)];
/// Peer extras are 16-hex hashes.
pub const PEER_HASH_FROM: VltVersion = VltVersion::release(1, 0, 8);
/// The global store and `store-linker`.
pub const STORE_LINKER_FROM: VltVersion = VltVersion::release(1, 2, 0);
/// Windows edges become junctions.
pub const JUNCTIONS_FROM: VltVersion = VltVersion::rc(22);
/// Lockless `file:` directory dependencies resolve again (broken from
/// 0.0.0-31).
pub const LOCKLESS_FILE_DIR_FROM: VltVersion = VltVersion::rc(6);

/// `npm:` alias specs resolve against public npm even with `registries.npm`
/// configured.
pub fn npm_alias_to_public_npm(v: VltVersion) -> bool {
    (VltVersion::rc(30)..=VltVersion::rc(32)).contains(&v)
}

/// A lockless install cannot resolve a `file:` directory dependency.
pub fn lockless_file_dir_broken(v: VltVersion) -> bool {
    (VltVersion::zero(31)..LOCKLESS_FILE_DIR_FROM).contains(&v)
}
/// `lockfileVersion` is checked (`ELOCKFILEVERSION`).
pub const LOCKFILE_VERSION_CHECKED_FROM: VltVersion = VltVersion::rc(15);
/// `vlt ci` installs optional dependencies from the lock of an
/// optional-only project.
pub const OPTIONAL_ONLY_CI_FROM: VltVersion = VltVersion::release(1, 0, 5);
/// `vlt install --force` exists.
pub const INSTALL_FORCE_FROM: VltVersion = VltVersion::rc(28);
/// `registries.npm` is required by install commands.
pub const REGISTRIES_NPM_REQUIRED_FROM: VltVersion = VltVersion::release(1, 0, 5);
/// vlt.json spells the scope map `scoped-registries` (`scope-registries`
/// before).
pub const SCOPED_REGISTRIES_KEY_FROM: VltVersion = VltVersion::rc(28);
/// `vlt update` exists.
pub const VLT_UPDATE_FROM: VltVersion = VltVersion::zero(20);
/// `vlt update` re-resolves an unchanged exact spec from the registry
/// (dropping a hosted pin); earlier releases keep the locked node.
pub const UPDATE_RERESOLVES_FROM: VltVersion = VltVersion::release(1, 0, 8);
/// Peer extras (`ṗ:N` / `peer.N`) exist.
pub const PEER_EXTRA_FROM: VltVersion = VltVersion::rc(6);
/// A workspace member's direct dependency whose peers resolve gets a peer
/// extra (`~peer.1`); the root importer's gets one from [`PEER_HASH_FROM`].
pub const MEMBER_PEER_EXTRA_FROM: VltVersion = VltVersion::rc(15);

/// Whether vlt writes a peer extra on a direct dependency with resolved
/// peers, for a workspace-member (`member`) or the root importer.
pub fn direct_peer_extra(v: VltVersion, member: bool) -> bool {
    if member {
        v >= MEMBER_PEER_EXTRA_FROM
    } else {
        v >= PEER_HASH_FROM
    }
}

/// Named registry specs (`acme:x@1`), scoped registries and URL-segment
/// DepIDs exist (flat-config releases record every registry node under
/// the default segment).
pub const REGISTRY_DEP_IDS_FROM: VltVersion = VltVersion::zero(14);

/// `jsr:` specs follow `jsr-registries` (0.0.0-14 … rc.6 send the `@jsr`
/// scope to npm.jsr.io whatever is configured).
pub const JSR_REGISTRIES_ROUTE_FROM: VltVersion = VltVersion::rc(7);

/// Re-saves (`vlt install <new>`) drop slot [3] of default-registry nodes,
/// keeping slot [2].
pub fn resave_drops_hosted_url(v: VltVersion) -> bool {
    (VltVersion::rc(6)..=VltVersion::rc(17)).contains(&v)
}

/// A platform-skipped optional dependency makes the install fail
/// (`Dependency node could not be found`).
pub fn platform_optional_install_bug(v: VltVersion) -> bool {
    (VltVersion::zero(31)..=VltVersion::rc(1)).contains(&v)
}

/// A warm cache re-fetches a tarball whose URL it holds and fails its
/// integrity when the bytes changed (no stale-bytes hazard).
pub fn warm_cache_reverifies(v: VltVersion) -> bool {
    (VltVersion::rc(27)..=VltVersion::release(1, 0, 2)).contains(&v)
}

/// After a hosted→vendored takeover that kept the hosted store copy, a
/// plain `vlt install` already links the vendored dir.
pub fn takeover_install_relinks(v: VltVersion) -> bool {
    v <= VltVersion::zero(29)
}

/// A plain `vlt install` re-extracts a stale installed copy.
pub fn plain_install_refreshes_stale(v: VltVersion) -> bool {
    v == VltVersion::zero(14)
}

/// What a lock-driven install does for a project whose dependencies are
/// all optional.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionalOnly {
    /// Installs them from the lock.
    Installs,
    /// The first install writes no `vlt-lock.json` at all.
    NoLock,
    /// Installs nothing from the lock.
    InstallsNothing,
}

pub fn optional_only(v: VltVersion) -> OptionalOnly {
    if v >= OPTIONAL_ONLY_CI_FROM || v <= VltVersion::zero(23) {
        OptionalOnly::Installs
    } else if v <= VltVersion::zero(29) {
        OptionalOnly::NoLock
    } else {
        OptionalOnly::InstallsNothing
    }
}

/// The lock is ignored unless vlt.json declares `"modifiers": {}`.
pub fn lock_ignored_without_modifiers(v: VltVersion) -> bool {
    (VltVersion::zero(16)..=VltVersion::zero(24)).contains(&v)
}

/// A scalar `registry` makes lock-driven installs re-resolve from npm.
pub fn scalar_registry_ignored(v: VltVersion) -> bool {
    (VltVersion::rc(7)..=VltVersion::rc(29)).contains(&v)
}

/// The harness can run every install against its own registry.
pub fn hermetic_registry(v: VltVersion) -> bool {
    !scalar_registry_ignored(v)
}

pub fn integrity_enforced(v: VltVersion) -> bool {
    !INTEGRITY_UNENFORCED.contains(&v)
}

/// vlt.json is flat (no `config` key).
pub fn flat_vlt_json(v: VltVersion) -> bool {
    v <= VltVersion::zero(13)
}

/// Workspaces live in `vlt-workspaces.json`.
pub fn legacy_workspaces_file(v: VltVersion) -> bool {
    v <= VltVersion::zero(12)
}

/// The lockfile grammar a release writes (DESIGN §1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VltEra {
    A0,
    A,
    B,
    C,
    D,
    E,
    F,
}

impl VltEra {
    pub fn from_version(v: VltVersion) -> Self {
        if v <= VltVersion::zero(18) {
            VltEra::A0
        } else if v <= VltVersion::rc(8) {
            VltEra::A
        } else if v <= VltVersion::rc(14) {
            VltEra::B
        } else if v <= VltVersion::rc(32) {
            VltEra::C
        } else if v < PEER_HASH_FROM {
            VltEra::D
        } else if v < STORE_LINKER_FROM {
            VltEra::E
        } else {
            VltEra::F
        }
    }

    /// The `lockfileVersion` this era writes.
    pub fn lockfile_version(self) -> Option<u64> {
        match self {
            VltEra::A0 => None,
            VltEra::A | VltEra::B => Some(0),
            _ => Some(1),
        }
    }

    /// Tilde (`~`) DepIDs rather than legacy (`·`) ones.
    pub fn tilde(self) -> bool {
        self >= VltEra::C
    }
}

pub fn os_name() -> &'static str {
    std::env::consts::OS
}

// ── the toolchain gate ────────────────────────────────────────────────────

/// The vlt under test.
#[derive(Clone, Debug)]
pub struct Toolchain {
    pub js: PathBuf,
    pub version: VltVersion,
    pub raw: String,
}

impl Toolchain {
    pub fn era(&self) -> VltEra {
        VltEra::from_version(self.version)
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn ci_is_true() -> bool {
    std::env::var("CI").is_ok_and(|v| v.eq_ignore_ascii_case("true"))
}

fn required() -> bool {
    env_nonempty("SOCKET_PATCH_VLT_E2E_REQUIRED").is_some()
        || env_nonempty("SOCKET_PATCH_VLT_E2E_JS").is_some()
        || ci_is_true()
}

/// `node --no-warnings <js> --version`.
pub fn probe_version(js: &Path) -> Result<String, String> {
    let mut cmd = Command::new("node");
    cmd.arg("--no-warnings").arg(js).arg("--version");
    scrub_for_vlt(&mut cmd);
    cmd.env("VLT_TELEMETRY", "0");
    let out = cmd
        .output()
        .map_err(|e| format!("cannot spawn node: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`vlt --version` exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default()
        .to_string())
}

fn resolve(js_var: &str, version_var: &str) -> Result<Option<Toolchain>, String> {
    let Some(js) = env_nonempty(js_var) else {
        return Ok(None);
    };
    let js = PathBuf::from(js);
    if !js.is_file() {
        return Err(format!("{js_var}={} is not a file", js.display()));
    }
    let raw = probe_version(&js)?;
    if let Some(want) = env_nonempty(version_var) {
        if want != raw {
            return Err(format!(
                "{version_var}={want} but `vlt --version` says {raw}"
            ));
        }
    }
    let version =
        VltVersion::parse(&raw).ok_or_else(|| format!("unparseable vlt version {raw}"))?;
    Ok(Some(Toolchain { js, version, raw }))
}

/// The vlt under test, resolved once per process.
pub fn toolchain() -> Result<Option<Toolchain>, String> {
    static CELL: OnceLock<Result<Option<Toolchain>, String>> = OnceLock::new();
    CELL.get_or_init(|| resolve("SOCKET_PATCH_VLT_E2E_JS", "SOCKET_PATCH_VLT_E2E_VERSION"))
        .clone()
}

/// The upgrade vlt (`_UPGRADE_JS`), if configured.
pub fn upgrade_toolchain() -> Result<Option<Toolchain>, String> {
    static CELL: OnceLock<Result<Option<Toolchain>, String>> = OnceLock::new();
    CELL.get_or_init(|| {
        resolve(
            "SOCKET_PATCH_VLT_E2E_UPGRADE_JS",
            "SOCKET_PATCH_VLT_E2E_UPGRADE_VERSION",
        )
    })
    .clone()
}

/// The configured `store-linker` knob.
pub fn store_linker() -> Option<String> {
    env_nonempty("SOCKET_PATCH_VLT_E2E_STORE_LINKER")
}

pub fn cache_root_knob() -> Option<PathBuf> {
    env_nonempty("SOCKET_PATCH_VLT_E2E_CACHE_ROOT").map(PathBuf::from)
}

/// The socket-patch binary under test.
pub fn socket_bin() -> PathBuf {
    env_nonempty("SOCKET_PATCH_VLT_E2E_SOCKET_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_socket-patch")))
}

// ── legs ──────────────────────────────────────────────────────────────────

/// The parent of every leg tempdir. vlt ≥ 1.2.0 writes cache entries from a
/// detached process after the command exits, which can recreate a deleted
/// leg's XDG cache path; the first leg of a run sweeps leftovers older than
/// an hour.
fn legs_root() -> PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join("vlt-e2e-legs");
        std::fs::create_dir_all(&root).expect("vlt-e2e-legs");
        let hour = std::time::Duration::from_secs(3600);
        for e in std::fs::read_dir(&root).into_iter().flatten().flatten() {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > hour);
            if old {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
        root
    })
    .clone()
}

pub fn leg_line(version: &str, suite: &str, leg: &str, status: &str) -> String {
    format!("VLT-LEG {version} {} {suite} {leg} {status}", os_name())
}

/// One `write` of the whole line, so libtest's own output never splits it.
fn print_leg(version: &str, suite: &str, leg: &str, status: &str) {
    let line = format!("\n{}\n", leg_line(version, suite, leg, status));
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    let _ = lock.write_all(line.as_bytes());
    let _ = lock.flush();
}

/// One running leg: the toolchain, a canonical private tempdir with its own
/// XDG tree, and the `VLT-LEG` line it owes.
pub struct Leg {
    pub suite: &'static str,
    pub name: &'static str,
    pub tc: Toolchain,
    tmp: tempfile::TempDir,
    pub root: PathBuf,
    cache_tmp: Option<tempfile::TempDir>,
    reported: bool,
}

impl Leg {
    /// Start `vlt_pinned_matrix_<suite>_<name>`. `None` when the toolchain
    /// is absent and not required (the skip line is already printed).
    pub fn start(suite: &'static str, name: &'static str) -> Option<Leg> {
        let tc = match toolchain() {
            Ok(Some(tc)) => tc,
            Ok(None) => {
                assert!(
                    !required(),
                    "vlt_pinned_matrix_{suite}_{name}: SOCKET_PATCH_VLT_E2E_JS is unset but \
                     a vlt toolchain is required (CI=true or SOCKET_PATCH_VLT_E2E_REQUIRED)"
                );
                print_leg("none", suite, name, "skip:no-vlt-toolchain");
                return None;
            }
            Err(e) => panic!("vlt_pinned_matrix_{suite}_{name}: {e}"),
        };
        let tmp = tempfile::Builder::new()
            .prefix("vlt-e2e-")
            .tempdir_in(legs_root())
            .expect("leg tempdir");
        let root = tmp.path().canonicalize().expect("canonical leg tempdir");
        let cache_tmp = cache_root_knob().map(|base| {
            std::fs::create_dir_all(&base).unwrap();
            tempfile::Builder::new()
                .prefix("vlt-e2e-cache-")
                .tempdir_in(base)
                .expect("cache-root tempdir")
        });
        Some(Leg {
            suite,
            name,
            tc,
            tmp,
            root,
            cache_tmp,
            reported: false,
        })
    }

    pub fn version(&self) -> VltVersion {
        self.tc.version
    }

    pub fn era(&self) -> VltEra {
        self.tc.era()
    }

    pub fn at_least(&self, v: VltVersion) -> bool {
        self.tc.version >= v
    }

    pub fn ran(mut self) {
        self.reported = true;
        print_leg(&self.tc.raw, self.suite, self.name, "ran");
    }

    pub fn skip(mut self, reason: &str) {
        self.reported = true;
        print_leg(
            &self.tc.raw,
            self.suite,
            self.name,
            &format!("skip:{reason}"),
        );
    }

    /// A fresh directory `<root>/<name>`.
    pub fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        if d.exists() {
            std::fs::remove_dir_all(&d).unwrap();
        }
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The XDG tree vlt uses for `profile` (legs that need separate caches
    /// use separate profiles).
    pub fn xdg(&self, profile: &str) -> Xdg {
        let base = self.root.join("xdg").join(profile);
        let cache = match &self.cache_tmp {
            Some(t) => t.path().join(profile),
            None => base.join("cache"),
        };
        let x = Xdg {
            cache,
            config: base.join("config"),
            data: base.join("data"),
            state: base.join("state"),
            runtime: base.join("run"),
        };
        for d in [&x.cache, &x.config, &x.data, &x.state, &x.runtime] {
            std::fs::create_dir_all(d).unwrap();
        }
        x
    }

    /// The directory holding the `npx` / `vlt` shims (created on first use).
    pub fn shim_dir(&self) -> PathBuf {
        let bin = self.root.join("bin");
        if !bin.join("npx").exists() {
            write_shims(&bin, &self.tc.js, &self.root.join("npx.log"));
        }
        bin
    }

    /// Lines the `npx` shim logged, one per hook invocation.
    pub fn npx_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.root.join("npx.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Run vlt in `cwd` with the `default` profile.
    pub fn vlt(&self, cwd: &Path, args: &[&str]) -> Output {
        self.vlt_with(cwd, args, &VltRun::default())
    }

    pub fn vlt_with(&self, cwd: &Path, args: &[&str], run: &VltRun) -> Output {
        let tc = run.tc.as_ref().unwrap_or(&self.tc);
        let xdg = self.xdg(run.profile.as_deref().unwrap_or("default"));
        let mut env: Vec<(String, String)> = xdg.vars();
        env.push(("DO_NOT_TRACK".into(), "1".into()));
        env.push(("CI".into(), "1".into()));
        if let Some(linker) = store_linker() {
            env.push(("VLT_STORE_LINKER".into(), linker));
        }
        if run.shims {
            let bin = self.shim_dir();
            let path = std::env::var_os("PATH").unwrap_or_default();
            let mut parts = vec![bin];
            parts.extend(std::env::split_paths(&path));
            let joined = std::env::join_paths(parts).unwrap();
            env.push(("PATH".into(), joined.to_string_lossy().into_owned()));
        }
        env.extend(run.env.iter().cloned());
        let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        common::vlt_run(cwd, &tc.js, args, &pairs)
    }

    /// [`Leg::vlt`], asserting success.
    pub fn vlt_ok(&self, cwd: &Path, args: &[&str]) -> Output {
        let out = self.vlt(cwd, args);
        assert_ok(&out, &format!("{} vlt {}", self.tc.raw, args.join(" ")));
        out
    }

    pub fn vlt_ok_with(&self, cwd: &Path, args: &[&str], run: &VltRun) -> Output {
        let out = self.vlt_with(cwd, args, run);
        assert_ok(&out, &format!("{} vlt {}", self.tc.raw, args.join(" ")));
        out
    }

    /// The command that installs exactly the lock: `vlt ci` from 0.0.0-19,
    /// else a plain `vlt install`.
    pub fn locked_install_args(&self) -> Vec<&'static str> {
        if self.at_least(HAS_CI_FROM) {
            vec!["ci"]
        } else {
            vec!["install"]
        }
    }

    pub fn frozen_args(&self) -> Vec<&'static str> {
        if self.at_least(HAS_CI_FROM) {
            vec!["install", "--frozen-lockfile"]
        } else {
            vec!["install"]
        }
    }

    /// The global store vlt 1.2.0 keeps under the default profile's cache.
    pub fn global_store(&self, profile: &str) -> PathBuf {
        self.xdg(profile).cache.join("vlt").join("store").join("v1")
    }
}

impl Drop for Leg {
    fn drop(&mut self) {
        if !self.reported && !std::thread::panicking() {
            eprintln!(
                "vlt_pinned_matrix_{}_{}: finished without a VLT-LEG line",
                self.suite, self.name
            );
        }
    }
}

/// Per-invocation options for [`Leg::vlt_with`].
#[derive(Default, Clone)]
pub struct VltRun {
    pub profile: Option<String>,
    pub tc: Option<Toolchain>,
    pub shims: bool,
    pub env: Vec<(String, String)>,
}

impl VltRun {
    pub fn profile(p: &str) -> Self {
        Self {
            profile: Some(p.to_string()),
            ..Self::default()
        }
    }

    pub fn with_env(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.to_string(), v.to_string()));
        self
    }

    pub fn with_tc(mut self, tc: &Toolchain) -> Self {
        self.tc = Some(tc.clone());
        self
    }

    pub fn with_shims(mut self) -> Self {
        self.shims = true;
        self
    }
}

pub struct Xdg {
    pub cache: PathBuf,
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
}

impl Xdg {
    fn vars(&self) -> Vec<(String, String)> {
        let s = |p: &Path| p.to_string_lossy().into_owned();
        vec![
            ("XDG_CACHE_HOME".into(), s(&self.cache)),
            ("XDG_CONFIG_HOME".into(), s(&self.config)),
            ("XDG_DATA_HOME".into(), s(&self.data)),
            ("XDG_STATE_HOME".into(), s(&self.state)),
            ("XDG_RUNTIME_DIR".into(), s(&self.runtime)),
            ("VLT_CACHE".into(), s(&self.cache.join("vlt"))),
        ]
    }
}

/// Remove the ambient vlt/npm/socket configuration from `cmd`.
pub fn scrub_for_vlt(cmd: &mut Command) {
    cache_env::scrub_ambient_vlt_env(cmd);
}

pub fn out_text(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub fn assert_ok(out: &Output, what: &str) {
    assert!(out.status.success(), "{what} failed: {}", out_text(out));
}

// ── shims ─────────────────────────────────────────────────────────────────

/// `npx` and `vlt` shims (sh and `.cmd`) in `bin`: `npx
/// @socketsecurity/socket-patch <args>` runs the socket-patch binary under
/// test and logs one line per invocation to `log`; `vlt` runs `js`.
pub fn write_shims(bin: &Path, js: &Path, log: &Path) {
    write_shims_for(bin, js, log, &socket_bin());
}

/// [`write_shims`] with the `npx` shim running `socket`. cmd.exe's `%*`
/// ignores `shift`, so the `.cmd` shim rebuilds the argument list after
/// the package token itself.
pub fn write_shims_for(bin: &Path, js: &Path, log: &Path, socket: &Path) {
    std::fs::create_dir_all(bin).unwrap();
    let sh_npx = format!(
        "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    @socketsecurity/socket-patch|@socketsecurity/socket-patch@*) shift; break;;\n    *) shift;;\n  esac\ndone\nprintf '%s\\n' \"npx $*\" >> '{log}'\nexec '{socket}' \"$@\"\n",
        log = log.display(),
        socket = socket.display()
    );
    let sh_vlt = format!(
        "#!/bin/sh\nexec node --no-warnings '{}' \"$@\"\n",
        js.display()
    );
    let cmd_npx = format!(
        "@echo off\r\nsetlocal\r\nset SP_ARGS=\r\n:loop\r\nif \"%~1\"==\"\" goto run\r\nset SP_PKG=%~1\r\nshift\r\nif \"%SP_PKG:~0,28%\"==\"@socketsecurity/socket-patch\" goto collect\r\ngoto loop\r\n:collect\r\nif \"%~1\"==\"\" goto run\r\nset SP_ARGS=%SP_ARGS% %1\r\nshift\r\ngoto collect\r\n:run\r\n>>\"{log}\" echo npx%SP_ARGS%\r\n\"{socket}\"%SP_ARGS%\r\n",
        log = log.display(),
        socket = socket.display()
    );
    let cmd_vlt = format!(
        "@echo off\r\nnode --no-warnings \"{}\" %*\r\n",
        js.display()
    );
    for (name, body) in [("npx", sh_npx), ("vlt", sh_vlt)] {
        let p = bin.join(name);
        std::fs::write(&p, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    std::fs::write(bin.join("npx.cmd"), cmd_npx).unwrap();
    std::fs::write(bin.join("vlt.cmd"), cmd_vlt).unwrap();
}

// ── vlt.json ──────────────────────────────────────────────────────────────

/// How a project reaches its registry.
#[derive(Clone, Debug, Default)]
pub struct VltJson {
    /// Extra members of `config` (after the registry keys).
    pub config: Vec<(String, Value)>,
    /// Workspace globs, if any.
    pub workspaces: Option<Value>,
    /// Suppress the `"modifiers": {}` the 0.0.0-16 … 24 window needs.
    pub no_modifiers: bool,
    /// Leave every registry key out (registry configured elsewhere).
    pub no_registry: bool,
}

/// The vlt.json the §8.3 era table prescribes for registry `r`
/// (`http://127.0.0.1:<port>/`).
pub fn vlt_json(v: VltVersion, r: &str, opts: &VltJson) -> Value {
    let mut config = serde_json::Map::new();
    if !opts.no_registry {
        if scalar_registry_ignored(v) {
            config.insert("registry".into(), json!("https://registry.npmjs.org/"));
        } else if v >= REGISTRIES_NPM_ROUTES_FROM {
            config.insert("registries".into(), json!({ "npm": r }));
            if v < REGISTRIES_NPM_REQUIRED_FROM {
                config.insert("registry".into(), json!(r));
            }
        } else {
            config.insert("registry".into(), json!(r));
        }
    }
    for (k, val) in &opts.config {
        config.insert(k.clone(), val.clone());
    }
    let mut doc = serde_json::Map::new();
    if flat_vlt_json(v) {
        doc = config;
    } else if !config.is_empty() {
        doc.insert("config".into(), Value::Object(config));
    }
    if lock_ignored_without_modifiers(v) && !opts.no_modifiers {
        doc.insert("modifiers".into(), json!({}));
    }
    if let Some(ws) = &opts.workspaces {
        if !legacy_workspaces_file(v) {
            doc.insert("workspaces".into(), ws.clone());
        }
    }
    Value::Object(doc)
}

/// Write `vlt.json` (and, ≤ 0.0.0-12, `vlt-workspaces.json`) into `proj`.
pub fn write_vlt_json(proj: &Path, v: VltVersion, r: &str, opts: &VltJson) {
    let doc = vlt_json(v, r, opts);
    std::fs::write(
        proj.join("vlt.json"),
        serde_json::to_string_pretty(&doc).unwrap() + "\n",
    )
    .unwrap();
    write_vlt_workspaces(proj, v, opts);
}

pub fn write_vlt_workspaces(proj: &Path, v: VltVersion, opts: &VltJson) {
    if let (true, Some(ws)) = (legacy_workspaces_file(v), &opts.workspaces) {
        std::fs::write(
            proj.join("vlt-workspaces.json"),
            serde_json::to_string_pretty(&json!({ "packages": ws })).unwrap() + "\n",
        )
        .unwrap();
    }
}

// ── the local npm registry ────────────────────────────────────────────────

/// `name@version` bytes fetched once from npmjs into the shared test cache.
#[derive(Clone)]
pub struct CachedPkg {
    pub name: String,
    pub version: String,
    pub manifest: Value,
    pub tgz: Vec<u8>,
}

impl CachedPkg {
    pub fn bare(&self) -> &str {
        self.name.rsplit('/').next().unwrap()
    }

    pub fn integrity(&self) -> String {
        sha512_sri(&self.tgz)
    }
}

fn registry_cache_dir() -> PathBuf {
    cache_env::cache_root().join("vlt-e2e-registry").join("v1")
}

fn cache_key(name: &str, version: &str) -> String {
    format!("{}@{version}", name.replace('/', "+"))
}

fn write_atomic(path: &Path, bytes: &[u8]) {
    let dir = path.parent().unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let mut tmp = tempfile::NamedTempFile::new_in(dir).unwrap();
    tmp.write_all(bytes).unwrap();
    tmp.persist(path).ok();
}

/// `name@version` from the shared cache, fetching it from npmjs (and
/// checking its integrity) the first time.
pub async fn fetch_pkg(name: &str, version: &str) -> CachedPkg {
    let dir = registry_cache_dir();
    let key = cache_key(name, version);
    let json_path = dir.join(format!("{key}.json"));
    let tgz_path = dir.join(format!("{key}.tgz"));
    if let (Ok(m), Ok(t)) = (std::fs::read(&json_path), std::fs::read(&tgz_path)) {
        if let Ok(manifest) = serde_json::from_slice::<Value>(&m) {
            if manifest["dist"]["integrity"].as_str() == Some(sha512_sri(&t).as_str()) {
                return CachedPkg {
                    name: name.into(),
                    version: version.into(),
                    manifest,
                    tgz: t,
                };
            }
        }
    }
    let client = reqwest::Client::new();
    let url = format!(
        "https://registry.npmjs.org/{}",
        name.replacen('/', "%2f", 1)
    );
    let mut last = String::new();
    for attempt in 0..5 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2 * attempt)).await;
        }
        let packument: Value = match client
            .get(&url)
            .header("accept", "application/json")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => match r.json().await {
                Ok(v) => v,
                Err(e) => {
                    last = e.to_string();
                    continue;
                }
            },
            Ok(r) => {
                last = format!("http {}", r.status());
                continue;
            }
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        let manifest = packument["versions"][version].clone();
        assert!(
            manifest.is_object(),
            "npmjs has no {name}@{version} (needed by the vlt e2e registry)"
        );
        let tarball = manifest["dist"]["tarball"].as_str().unwrap().to_string();
        let tgz = match client.get(&tarball).send().await {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    last = e.to_string();
                    continue;
                }
            },
            Ok(r) => {
                last = format!("http {}", r.status());
                continue;
            }
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        let want = manifest["dist"]["integrity"].as_str().unwrap_or_default();
        assert_eq!(
            sha512_sri(&tgz),
            want,
            "npmjs served {name}@{version} bytes that fail its own integrity"
        );
        write_atomic(&json_path, &serde_json::to_vec(&manifest).unwrap());
        write_atomic(&tgz_path, &tgz);
        return CachedPkg {
            name: name.into(),
            version: version.into(),
            manifest,
            tgz,
        };
    }
    panic!("could not fetch {name}@{version} from npmjs for the vlt e2e registry: {last}");
}

/// A harness-built package (`files` are package-relative; package.json is
/// generated from `manifest`).
pub fn synthetic_pkg(manifest: Value, files: &[(&str, &[u8])]) -> CachedPkg {
    let mut tree = BTreeMap::new();
    tree.insert(
        "package.json".to_string(),
        (serde_json::to_string_pretty(&manifest).unwrap() + "\n").into_bytes(),
    );
    for (rel, bytes) in files {
        tree.insert((*rel).to_string(), bytes.to_vec());
    }
    let tgz = build_tgz(&tree);
    let mut manifest = manifest;
    manifest["dist"] = json!({ "integrity": sha512_sri(&tgz), "tarball": "" });
    CachedPkg {
        name: manifest["name"].as_str().unwrap().to_string(),
        version: manifest["version"].as_str().unwrap().to_string(),
        manifest,
        tgz,
    }
}

/// [`synthetic_pkg`] with `exec` entries marked executable.
pub fn synthetic_pkg_exec(manifest: Value, files: &[(&str, &[u8])], exec: &[&str]) -> CachedPkg {
    let mut tree = BTreeMap::new();
    tree.insert(
        "package.json".to_string(),
        (serde_json::to_string_pretty(&manifest).unwrap() + "\n").into_bytes(),
    );
    for (rel, bytes) in files {
        tree.insert((*rel).to_string(), bytes.to_vec());
    }
    let tgz = build_tgz_with(&tree, exec);
    let mut manifest = manifest;
    manifest["dist"] = json!({ "integrity": sha512_sri(&tgz), "tarball": "" });
    CachedPkg {
        name: manifest["name"].as_str().unwrap().to_string(),
        version: manifest["version"].as_str().unwrap().to_string(),
        manifest,
        tgz,
    }
}

/// A peer-free package that `require()`s its own name
/// (`vlt-e2e-selfref/lib/impl`), the D19 self-reference probe.
pub fn selfref_pkg() -> CachedPkg {
    synthetic_pkg(
        json!({ "name": "vlt-e2e-selfref", "version": "1.0.0", "main": "index.js" }),
        &[
            (
                "index.js",
                b"module.exports = require('vlt-e2e-selfref/lib/impl');\n",
            ),
            ("lib/impl.js", b"module.exports = 'impl';\n"),
        ],
    )
}

/// A wiremock npm registry serving exactly the pinned `name@version` set,
/// from bytes fetched once from npmjs.
pub struct Registry {
    pub server: MockServer,
    pub pkgs: Vec<CachedPkg>,
}

fn escape_name_regex(name: &str) -> String {
    match name.split_once('/') {
        Some((scope, bare)) => {
            format!("^/{}(%2[fF]|/){}$", regex_escape(scope), regex_escape(bare))
        }
        None => format!("^/{}$", regex_escape(name)),
    }
}

fn regex_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl Registry {
    pub async fn start(pins: &[(&str, &str)]) -> Registry {
        Registry::start_with(pins, Vec::new()).await
    }

    /// [`Registry::start`] plus harness-built `synthetic` packages.
    pub async fn start_with(pins: &[(&str, &str)], synthetic: Vec<CachedPkg>) -> Registry {
        let mut pkgs = Vec::new();
        for (name, version) in pins {
            pkgs.push(fetch_pkg(name, version).await);
        }
        pkgs.extend(synthetic);
        let server = MockServer::start().await;
        let reg = Registry { server, pkgs };
        reg.mount().await;
        reg
    }

    /// `http://127.0.0.1:<port>/`.
    pub fn url(&self) -> String {
        format!("{}/", self.server.uri())
    }

    pub fn tarball_path(name: &str, bare: &str, version: &str) -> String {
        format!("/{name}/-/{bare}-{version}.tgz")
    }

    pub fn pkg(&self, name: &str, version: &str) -> &CachedPkg {
        self.pkgs
            .iter()
            .find(|p| p.name == name && p.version == version)
            .unwrap_or_else(|| panic!("{name}@{version} is not pinned in the registry"))
    }

    pub fn packument(&self, name: &str) -> Value {
        let mut versions = serde_json::Map::new();
        let mut latest: Option<String> = None;
        for p in self.pkgs.iter().filter(|p| p.name == name) {
            let mut m = p.manifest.clone();
            m["dist"]["tarball"] = json!(format!(
                "{}{}",
                self.server.uri(),
                Self::tarball_path(&p.name, p.bare(), &p.version)
            ));
            versions.insert(p.version.clone(), m);
            latest = Some(p.version.clone());
        }
        let mut times = serde_json::Map::new();
        for v in versions.keys() {
            times.insert(v.clone(), json!("2020-01-01T00:00:00.000Z"));
        }
        json!({
            "name": name,
            "dist-tags": { "latest": latest },
            "versions": versions,
            "time": times,
        })
    }

    pub async fn mount(&self) {
        let mut names: Vec<&str> = self.pkgs.iter().map(|p| p.name.as_str()).collect();
        names.sort();
        names.dedup();
        for name in names {
            Mock::given(method("GET"))
                .and(path_regex(escape_name_regex(name)))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/json")
                        .set_body_json(self.packument(name)),
                )
                .mount(&self.server)
                .await;
        }
        for p in &self.pkgs {
            let mut m = p.manifest.clone();
            m["dist"]["tarball"] = json!(format!(
                "{}{}",
                self.server.uri(),
                Self::tarball_path(&p.name, p.bare(), &p.version)
            ));
            let doc_path = format!(
                "{}/{}$",
                escape_name_regex(&p.name).trim_end_matches('$'),
                regex_escape(&p.version)
            );
            Mock::given(method("GET"))
                .and(path_regex(doc_path))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/json")
                        .set_body_json(m),
                )
                .mount(&self.server)
                .await;
            Mock::given(method("GET"))
                .and(path(Self::tarball_path(&p.name, p.bare(), &p.version)))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/octet-stream")
                        .set_body_bytes(p.tgz.clone()),
                )
                .mount(&self.server)
                .await;
        }
    }

    /// Every route answers 404 from now on (the URL stays the same, so
    /// the lock's `options` do not change).
    pub async fn kill(&self) {
        self.server.reset().await;
    }

    pub async fn revive(&self) {
        self.server.reset().await;
        self.mount().await;
    }

    pub async fn requests(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }
}

// ── hashing and tarballs ──────────────────────────────────────────────────

pub fn sha512_sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn git_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(format!("blob {}\0", bytes.len()).as_bytes());
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Every regular file under `dir` (relative, forward-slashed), skipping
/// `node_modules` and following no links.
pub fn package_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let ty = e.file_type().unwrap();
            let p = e.path();
            if ty.is_dir() {
                if e.file_name() == "node_modules" {
                    continue;
                }
                walk(base, &p, out);
            } else if ty.is_file() {
                let rel = p
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

/// A deterministic npm tarball (`package/` prefix, zero mtimes, sorted
/// entries, a fixed gzip header).
pub fn build_tgz(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    build_tgz_with(files, &[])
}

/// [`build_tgz`] with `exec` entries (and `bin/*`) at mode 0755.
pub fn build_tgz_with(files: &BTreeMap<String, Vec<u8>>, exec: &[&str]) -> Vec<u8> {
    let gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::new(6));
    let mut builder = tar::Builder::new(gz);
    builder.mode(tar::HeaderMode::Deterministic);
    for (rel, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        let executable = rel.starts_with("bin/") || exec.contains(&rel.as_str());
        header.set_mode(if executable { 0o755 } else { 0o644 });
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("package/{rel}"), data.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// The files of a registry tarball, `package/` (or whatever the first
/// component is) stripped.
pub fn tgz_files(tgz: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(tgz));
    for entry in ar.entries().unwrap() {
        let mut entry = entry.unwrap();
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let p = entry.path().unwrap().to_string_lossy().replace('\\', "/");
        let rel = match p.split_once('/') {
            Some((_, rest)) => rest.to_string(),
            None => continue,
        };
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut buf).unwrap();
        out.insert(rel, buf);
    }
    out
}

// ── patch targets and the patch service ───────────────────────────────────

pub const ORG: &str = "test-org";
pub const TOKEN: &str = "44444444-4444-4444-8444-444444444444";
pub const MARKER: &[u8] = b"/* SOCKET-PATCHED */\n";
pub const TAMPER_MARKER: &[u8] = b"/* SOCKET-TAMPERED */\n";
pub const PRODUCT: &str = "pkg:npm/vlt-e2e-app@1.0.0";

/// One Socket patch the mock service publishes.
#[derive(Clone)]
pub struct PatchTarget {
    pub name: String,
    pub version: String,
    pub uuid: String,
    pub ghsa: String,
    pub cve: String,
    /// Package-relative path of the patched file.
    pub file: String,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
    /// Extra patched files `(rel, before, after)`.
    pub extra: Vec<(String, Vec<u8>, Vec<u8>)>,
    /// The hosted artifact (identity-encoded, deterministic).
    pub tgz: Vec<u8>,
    /// The pristine package files.
    pub base: BTreeMap<String, Vec<u8>>,
}

impl PatchTarget {
    /// Patch `file` of the pristine `pkg` by prepending [`MARKER`].
    pub fn from_pkg(pkg: &CachedPkg, uuid: &str, file: &str) -> Self {
        let files = tgz_files(&pkg.tgz);
        Self::from_files(&pkg.name, &pkg.version, uuid, file, files)
    }

    /// Patch `file` of the package whose installed files are `files`.
    pub fn from_files(
        name: &str,
        version: &str,
        uuid: &str,
        file: &str,
        mut files: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        let before = files
            .get(file)
            .unwrap_or_else(|| panic!("{name}@{version} has no {file}"))
            .clone();
        let after = [MARKER, before.as_slice()].concat();
        let base = files.clone();
        files.insert(file.to_string(), after.clone());
        let tgz = build_tgz(&files);
        let n = uuid.as_bytes()[0];
        Self {
            name: name.into(),
            version: version.into(),
            uuid: uuid.into(),
            ghsa: format!(
                "GHSA-vlte-{}{}{}{}-2e2e",
                n as char, n as char, n as char, n as char
            ),
            cve: format!("CVE-2026-{}", 4000 + u32::from(n)),
            file: file.into(),
            before,
            after,
            extra: Vec::new(),
            tgz,
            base,
        }
    }

    /// Also patch `rel` to `after` (the artifact is rebuilt).
    pub fn also_patch(mut self, rel: &str, after: Vec<u8>) -> Self {
        let before = self
            .base
            .get(rel)
            .unwrap_or_else(|| panic!("{} has no {rel}", self.name))
            .clone();
        self.extra.push((rel.to_string(), before, after));
        let mut files = self.base.clone();
        for (rel, _, after) in self.all_files() {
            files.insert(rel, after);
        }
        self.tgz = build_tgz(&files);
        self
    }

    /// Patch a file from the installed copy at `dir` (canonicalized
    /// through the importer link).
    pub fn from_installed(name: &str, version: &str, uuid: &str, file: &str, dir: &Path) -> Self {
        let real = dir.canonicalize().expect("installed package dir");
        Self::from_files(name, version, uuid, file, package_files(&real))
    }

    pub fn purl(&self) -> String {
        format!(
            "pkg:npm/{}@{}",
            self.name.replacen('@', "%40", 1),
            self.version
        )
    }

    pub fn bare(&self) -> &str {
        self.name.rsplit('/').next().unwrap()
    }

    pub fn sri(&self) -> String {
        sha512_sri(&self.tgz)
    }

    pub fn artifact_path(&self) -> String {
        format!(
            "/patch/npm/{}/{}/{TOKEN}/{}/{}-{}.tgz",
            self.name,
            self.version,
            self.uuid,
            self.bare(),
            self.version
        )
    }

    /// The vendored service's prebuilt archive route.
    pub fn prebuilt_path(&self) -> String {
        format!("/serve/{}/{}-{}.tgz", self.uuid, self.bare(), self.version)
    }

    pub fn all_files(&self) -> Vec<(String, Vec<u8>, Vec<u8>)> {
        let mut v = vec![(self.file.clone(), self.before.clone(), self.after.clone())];
        v.extend(self.extra.iter().cloned());
        v
    }

    pub fn view(&self) -> Value {
        let mut files = serde_json::Map::new();
        for (rel, before, after) in self.all_files() {
            files.insert(
                format!("package/{rel}"),
                json!({
                    "beforeHash": git_sha256(&before),
                    "afterHash": git_sha256(&after),
                    "blobContent": base64::engine::general_purpose::STANDARD.encode(&after),
                }),
            );
        }
        json!({
            "uuid": self.uuid,
            "purl": self.purl(),
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": files,
            "vulnerabilities": {
                self.ghsa.clone(): {
                    "cves": [self.cve],
                    "summary": "vlt e2e fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "vlt e2e fixture",
            "license": "MIT",
            "tier": "free"
        })
    }

    /// The patched package files (the artifact's content).
    pub fn patched_files(&self) -> BTreeMap<String, Vec<u8>> {
        tgz_files(&self.tgz)
    }

    /// `(package/<file>, afterHash)` for the VEX matrix.
    pub fn vex_files(&self) -> Vec<(String, String)> {
        self.all_files()
            .into_iter()
            .map(|(rel, _, after)| (format!("package/{rel}"), git_sha256(&after)))
            .collect()
    }
}

/// The mock Socket API plus the hosted artifact and prebuilt routes.
pub struct PatchService {
    pub server: MockServer,
    pub targets: Vec<PatchTarget>,
}

impl PatchService {
    pub async fn start(targets: Vec<PatchTarget>) -> PatchService {
        let server = MockServer::start().await;
        let svc = PatchService { server, targets };
        svc.mount_api().await;
        for t in &svc.targets {
            svc.serve_artifact(t, t.tgz.clone(), 5).await;
        }
        svc
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn target(&self, name: &str) -> &PatchTarget {
        self.targets
            .iter()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("no patch target {name}"))
    }

    pub fn artifact_url(&self, t: &PatchTarget) -> String {
        format!("{}{}", self.server.uri(), t.artifact_path())
    }

    async fn mount_api(&self) {
        let packages: Vec<Value> = self
            .targets
            .iter()
            .map(|t| {
                json!({
                    "purl": t.purl(),
                    "patches": [{
                        "uuid": t.uuid, "purl": t.purl(), "tier": "free",
                        "cveIds": [t.cve], "ghsaIds": [t.ghsa], "severity": "high",
                        "title": "vlt e2e fixture"
                    }]
                })
            })
            .collect();
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "packages": packages,
                "canAccessPaidPatches": false,
            })))
            .mount(&self.server)
            .await;
        for t in &self.targets {
            let encoded = urlencode(&t.purl());
            let alt = urlencode(&t.purl().replace("%40", "@"));
            for p in [encoded, alt] {
                Mock::given(method("GET"))
                    .and(path(format!("/v0/orgs/{ORG}/patches/by-package/{p}")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "patches": [{
                            "uuid": t.uuid, "purl": t.purl(),
                            "publishedAt": "2026-01-01T00:00:00Z",
                            "description": "x", "license": "MIT", "tier": "free",
                            "vulnerabilities": {}
                        }],
                        "canAccessPaidPatches": false,
                    })))
                    .mount(&self.server)
                    .await;
            }
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{}", t.uuid)))
                .respond_with(ResponseTemplate::new(200).set_body_json(t.view()))
                .mount(&self.server)
                .await;
        }
        for t in &self.targets {
            for (_, before, after) in t.all_files() {
                for bytes in [before, after] {
                    Mock::given(method("GET"))
                        .and(path(format!(
                            "/v0/orgs/{ORG}/patches/blob/{}",
                            git_sha256(&bytes)
                        )))
                        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
                        .mount(&self.server)
                        .await;
                }
            }
        }
        let mut results = serde_json::Map::new();
        for t in &self.targets {
            let url = self.artifact_url(t);
            results.insert(
                t.uuid.clone(),
                json!({
                    "status": "granted",
                    "url": url,
                    "purl": t.purl(),
                    "artifacts": [{
                        "kind": "tarball",
                        "url": url,
                        "integrity": { "sha512": t.sri() }
                    }],
                    "registryOverride": null
                }),
            );
        }
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/package")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": results })))
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.+$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "patches": [],
                "canAccessPaidPatches": false,
            })))
            .with_priority(9)
            .mount(&self.server)
            .await;
    }

    /// Serve `bytes` on `t`'s artifact route (identity-encoded) at
    /// wiremock `priority` (1 wins over the default 5).
    pub async fn serve_artifact(&self, t: &PatchTarget, bytes: Vec<u8>, priority: u8) {
        Mock::given(method("GET"))
            .and(path(t.artifact_path()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(bytes),
            )
            .with_priority(priority)
            .mount(&self.server)
            .await;
    }

    /// Serve `t`'s artifact gzip-encoded, as patch.socket.dev did before
    /// the `no-transform` fix.
    pub async fn serve_artifact_gzip_encoded(&self, t: &PatchTarget) {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&t.tgz).unwrap();
        Mock::given(method("GET"))
            .and(path(t.artifact_path()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(enc.finish().unwrap()),
            )
            .with_priority(1)
            .mount(&self.server)
            .await;
    }

    pub async fn artifact_hits(&self, t: &PatchTarget) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == t.artifact_path())
            .count()
    }

    pub async fn request_paths(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect()
    }
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ── socket-patch ──────────────────────────────────────────────────────────

/// The socket-patch binary with the ambient `SOCKET_*`, `VLT_*`, npm and
/// proxy environment scrubbed.
pub fn socket_cmd() -> Command {
    let mut cmd = Command::new(socket_bin());
    cache_env::scrub_ambient_vlt_env(&mut cmd);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if ["http_proxy", "https_proxy", "all_proxy", "no_proxy"]
            .iter()
            .any(|p| name.eq_ignore_ascii_case(p))
            || name.starts_with("SOCKET_PATCH_VLT_E2E_")
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_UPDATE_CHECK", "1")
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("VLT_TELEMETRY", "0")
        .env("LANG", "C")
        .env("LC_ALL", "C");
    cmd
}

pub struct SocketOut {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl SocketOut {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "socket-patch stdout is not JSON ({e}):\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

impl std::fmt::Display for SocketOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit {}\nstdout:\n{}\nstderr:\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// `socket-patch <args>` in `cwd` with `env`.
pub fn socket(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> SocketOut {
    let mut cmd = socket_cmd();
    cmd.args(args).current_dir(cwd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn socket-patch");
    SocketOut {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `<cmd> … --json --yes --cwd <proj> --api-url <svc> --org --api-token`.
pub fn socket_api(proj: &Path, svc: &PatchService, head: &[&str], extra: &[&str]) -> SocketOut {
    let cwd = proj.to_str().unwrap().to_string();
    let uri = svc.uri();
    let mut args: Vec<&str> = head.to_vec();
    args.extend([
        "--json",
        "--yes",
        "--cwd",
        &cwd,
        "--api-url",
        &uri,
        "--org",
        ORG,
        "--api-token",
        "sktsec_placeholder_value_for_tests_api",
    ]);
    args.extend_from_slice(extra);
    socket(proj, &args, &[])
}

/// `scan --mode hosted` with `extra`, asserting exit 0.
pub fn scan_hosted(proj: &Path, svc: &PatchService, extra: &[&str]) -> Value {
    let out = socket_api(proj, svc, &["scan", "--mode", "hosted"], extra);
    assert_eq!(out.code, 0, "scan --mode hosted: {out}");
    out.json()
}

/// `get <uuid> --mode hosted`, asserting exit 0.
pub fn get_hosted(proj: &Path, svc: &PatchService, uuid: &str, extra: &[&str]) -> Value {
    let out = socket_api(proj, svc, &["get", uuid, "--mode", "hosted"], extra);
    assert_eq!(out.code, 0, "get --mode hosted: {out}");
    out.json()
}

/// `rollback --yes --json` (whole ledger) in `proj`.
pub fn rollback(proj: &Path, extra: &[&str]) -> SocketOut {
    let cwd = proj.to_str().unwrap().to_string();
    let mut args = vec!["rollback", "--json", "--yes", "--cwd", &cwd];
    args.extend_from_slice(extra);
    socket(proj, &args, &[])
}

pub fn redirect_warnings(doc: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for w in [&doc["redirect"]["warnings"], &doc["warnings"]] {
        for w in w.as_array().into_iter().flatten() {
            if let Some(code) = w["code"].as_str() {
                out.push((
                    code.to_string(),
                    w["detail"].as_str().unwrap_or_default().to_string(),
                ));
            }
        }
    }
    out
}

pub fn warning_detail(doc: &Value, code: &str) -> String {
    redirect_warnings(doc)
        .into_iter()
        .find(|(c, _)| c == code)
        .map(|(_, d)| d)
        .unwrap_or_else(|| panic!("expected a `{code}` warning: {doc:#}"))
}

pub fn has_warning(doc: &Value, code: &str) -> bool {
    redirect_warnings(doc).iter().any(|(c, _)| c == code)
        || doc.to_string().contains(&format!("\"{code}\""))
}

// ── the lock ──────────────────────────────────────────────────────────────

pub const VLT_LOCK: &str = "vlt-lock.json";
pub const HIDDEN_LOCK: &str = "node_modules/.vlt-lock.json";

pub fn read_lock(proj: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(proj.join(VLT_LOCK)).expect("vlt-lock.json"))
        .expect("vlt-lock.json parses")
}

pub fn lock_bytes(proj: &Path) -> Vec<u8> {
    std::fs::read(proj.join(VLT_LOCK)).expect("vlt-lock.json")
}

/// vlt's tilde segment decode (DESIGN §1.6).
pub fn tilde_decode(seg: &str) -> String {
    let chars: Vec<char> = seg.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '+' {
            out.push('/');
            i += 1;
            continue;
        }
        if c == '_' && i + 1 < chars.len() {
            let n = chars[i + 1];
            let mapped = match n {
                '_' => Some('_'),
                'p' => Some('+'),
                'b' => Some('\\'),
                'c' => Some(':'),
                't' => Some('~'),
                'l' => Some('<'),
                'g' => Some('>'),
                'q' => Some('"'),
                'i' => Some('|'),
                'm' => Some('?'),
                'a' => Some('*'),
                'd' => Some('.'),
                's' => Some(' '),
                _ => None,
            };
            if let Some(m) = mapped {
                out.push(m);
                i += 2;
                continue;
            }
            if (n == '0' || n == '1') && i + 2 < chars.len() && chars[i + 2].is_ascii_hexdigit() {
                let v = u32::from_str_radix(&format!("{n}{}", chars[i + 2]), 16).unwrap();
                out.push(char::from_u32(v).unwrap());
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// `decodeURIComponent` of a legacy segment (`§` = `/`); `None` when
/// malformed.
pub fn legacy_decode(seg: &str) -> Option<String> {
    let s = seg.replace('§', "%2F");
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `(registry segment, name, version)` of a registry-type DepID.
pub fn decode_registry_id(id: &str) -> Option<(String, String, String)> {
    let (delim, tilde) = if id.starts_with('~') {
        ('~', true)
    } else if id.starts_with('·') {
        ('·', false)
    } else {
        return None;
    };
    let mut fields = id.splitn(4, delim);
    fields.next()?;
    let seg = fields.next()?;
    let second = fields.next()?;
    let decode = |s: &str| {
        if tilde {
            Some(tilde_decode(s))
        } else {
            legacy_decode(s)
        }
    };
    let seg = decode(seg)?;
    let nv = decode(second)?;
    let at = nv.rfind('@').filter(|i| *i > 0)?;
    Some((seg, nv[..at].to_string(), nv[at + 1..].to_string()))
}

/// The registry-type DepIDs whose tuple names `name` at `version`.
pub fn node_ids(lock: &Value, name: &str, version: &str) -> Vec<String> {
    lock["nodes"]
        .as_object()
        .map(|nodes| {
            nodes
                .iter()
                .filter(|(id, t)| {
                    t[1] == name
                        && decode_registry_id(id).is_some_and(|(_, n, v)| n == name && v == version)
                })
                .map(|(id, _)| id.clone())
                .collect()
        })
        .unwrap_or_default()
}

pub fn node_id(lock: &Value, name: &str, version: &str) -> String {
    let ids = node_ids(lock, name, version);
    assert_eq!(ids.len(), 1, "one node for {name}@{version}: {lock:#}");
    ids[0].clone()
}

/// The raw line of node `id` in the lock text.
pub fn node_line(text: &str, id: &str) -> Option<String> {
    let key = format!("\"{id}\": [");
    text.lines()
        .find(|l| l.trim_start().starts_with(&key))
        .map(str::to_string)
}

/// The era assertion: the lock the toolchain wrote has the expected
/// `lockfileVersion` and DepID family.
pub fn assert_lock_era(leg: &Leg, proj: &Path) {
    let lock = read_lock(proj);
    let era = leg.era();
    assert_eq!(
        lock["lockfileVersion"].as_u64(),
        era.lockfile_version(),
        "vlt {} wrote an unexpected lockfileVersion (era {era:?}): {lock:#}",
        leg.tc.raw
    );
    if let Some(nodes) = lock["nodes"].as_object() {
        for id in nodes.keys() {
            let tilde = id.starts_with('~') || id.contains('~') && !id.contains('·');
            if era.tilde() {
                assert!(tilde || !id.contains('·'), "era {era:?} DepID {id}");
            } else {
                assert!(id.contains('·'), "era {era:?} DepID {id}");
            }
        }
    }
}

/// Assert slot [2]/[3] of every `name@version` node pin the hosted artifact.
pub fn assert_pinned(proj: &Path, svc: &PatchService, t: &PatchTarget) {
    let lock = read_lock(proj);
    let ids = node_ids(&lock, &t.name, &t.version);
    assert!(!ids.is_empty(), "no node for {}: {lock:#}", t.name);
    for id in ids {
        let tuple = &lock["nodes"][&id];
        assert_eq!(tuple[2], t.sri(), "{id} slot [2]: {lock:#}");
        assert_eq!(tuple[3], svc.artifact_url(t), "{id} slot [3]: {lock:#}");
    }
}

pub fn assert_not_pinned(proj: &Path, t: &PatchTarget) {
    let lock = read_lock(proj);
    for id in node_ids(&lock, &t.name, &t.version) {
        assert_ne!(
            lock["nodes"][&id][2],
            t.sri(),
            "{id} must not be pinned: {lock:#}"
        );
    }
}

// ── the installed tree ────────────────────────────────────────────────────

/// `node_modules/<name>` of `importer` (relative to `proj`).
pub fn importer_dir(proj: &Path, importer: &str, name: &str) -> PathBuf {
    let base = if importer.is_empty() {
        proj.to_path_buf()
    } else {
        proj.join(importer)
    };
    base.join("node_modules").join(name)
}

/// The bytes of `rel` in `name` as the root importer sees it (through the
/// link), `None` when absent.
pub fn installed(proj: &Path, name: &str, rel: &str) -> Option<Vec<u8>> {
    std::fs::read(importer_dir(proj, "", name).join(rel)).ok()
}

/// Installed state of a patch target at the root importer.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    Patched,
    Pristine,
    Tampered,
    Other,
    Absent,
}

pub fn state_at(dir: &Path, t: &PatchTarget) -> State {
    match std::fs::read(dir.join(&t.file)) {
        Err(_) => State::Absent,
        Ok(b) if b == t.after => State::Patched,
        Ok(b) if b == t.before => State::Pristine,
        Ok(b) if b.starts_with(TAMPER_MARKER) => State::Tampered,
        Ok(_) => State::Other,
    }
}

pub fn state(proj: &Path, t: &PatchTarget) -> State {
    state_at(&importer_dir(proj, "", &t.name), t)
}

pub fn store_entry(proj: &Path, id: &str) -> PathBuf {
    proj.join("node_modules/.vlt").join(id)
}

/// `node_modules/.vlt/<id>/node_modules/<name>`.
pub fn store_pkg(proj: &Path, id: &str, name: &str) -> PathBuf {
    store_entry(proj, id).join("node_modules").join(name)
}

pub fn hidden_lock_exists(proj: &Path) -> bool {
    proj.join(HIDDEN_LOCK).exists()
}

/// Copy what a git checkout of `proj` would hold into `dest`: every file
/// but installed `node_modules` trees (a vendored payload's
/// `.socket/vendor/…/<leaf>/node_modules/<name>` travels; vlt's link dir
/// inside it does not) and links.
pub fn fresh_checkout(proj: &Path, dest: &Path) -> PathBuf {
    fn walk(src: &Path, dst: &Path, rel: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        let Ok(rd) = std::fs::read_dir(src) else {
            return;
        };
        for e in rd.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().starts_with(".VLT.DELETE") {
                continue;
            }
            let Ok(ty) = e.file_type() else {
                continue;
            };
            let child = rel.join(&name);
            if ty.is_symlink() {
                continue;
            }
            if ty.is_dir() {
                if name == "node_modules" && !travels(&child) {
                    continue;
                }
                walk(&e.path(), &dst.join(&name), &child);
            } else if ty.is_file() {
                match std::fs::copy(e.path(), dst.join(&name)) {
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => panic!("copy {}: {err}", e.path().display()),
                }
            }
        }
    }
    fn travels(rel: &Path) -> bool {
        let parts: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        parts.first().map(String::as_str) == Some(".socket")
            && parts.iter().filter(|p| *p == "node_modules").count() == 1
    }
    if dest.exists() {
        std::fs::remove_dir_all(dest).unwrap();
    }
    walk(proj, dest, Path::new(""));
    dest.to_path_buf()
}

pub fn write(path: &Path, body: impl AsRef<[u8]>) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(path, body).unwrap();
}

pub fn package_json(name: &str, deps: &[(&str, &str)]) -> String {
    package_json_fields(name, &[("dependencies", deps)])
}

pub fn package_json_fields(name: &str, fields: &[(&str, &[(&str, &str)])]) -> String {
    let mut doc = serde_json::Map::new();
    doc.insert("name".into(), json!(name));
    doc.insert("version".into(), json!("1.0.0"));
    for (field, deps) in fields {
        let mut m = serde_json::Map::new();
        for (k, v) in *deps {
            m.insert((*k).to_string(), json!(v));
        }
        doc.insert((*field).to_string(), Value::Object(m));
    }
    serde_json::to_string_pretty(&Value::Object(doc)).unwrap() + "\n"
}

pub fn to_crlf(text: &[u8]) -> Vec<u8> {
    let s = String::from_utf8(text.to_vec()).unwrap();
    s.replace("\r\n", "\n").replace('\n', "\r\n").into_bytes()
}

// ── the link-target snapshot (r-tests T15) ────────────────────────────────

/// Every `node_modules/.vlt/*` entry except `exclude`, plus (vlt ≥ 1.2.0)
/// the whole global store: file hashes, link targets and (Unix) inodes.
#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot(BTreeMap<String, String>);

fn snap_walk(label: &str, base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.map(|e| e.unwrap()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let rel = format!(
            "{label}/{}",
            p.strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        );
        let meta = std::fs::symlink_metadata(&p).unwrap();
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&p)
                .map(|t| t.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.insert(rel, format!("link {target}"));
        } else if meta.is_dir() {
            out.insert(rel.clone(), "dir".into());
            snap_walk(label, base, &p, out);
        } else {
            let bytes = std::fs::read(&p).unwrap_or_default();
            out.insert(rel, format!("file {} {}", sha256_hex(&bytes), inode(&meta)));
        }
    }
}

#[cfg(unix)]
fn inode(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt as _;
    format!("ino={}", meta.ino())
}

#[cfg(not(unix))]
fn inode(_meta: &std::fs::Metadata) -> String {
    String::new()
}

impl Snapshot {
    pub fn take(proj: &Path, exclude: &[String], store: Option<&Path>) -> Snapshot {
        let mut out = BTreeMap::new();
        let vlt = proj.join("node_modules/.vlt");
        if let Ok(rd) = std::fs::read_dir(&vlt) {
            for e in rd {
                let e = e.unwrap();
                let name = e.file_name().to_string_lossy().into_owned();
                if exclude.contains(&name) || name.starts_with(".VLT.DELETE") {
                    continue;
                }
                let mut one = BTreeMap::new();
                let p = e.path();
                let meta = std::fs::symlink_metadata(&p).unwrap();
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    snap_walk(&format!(".vlt/{name}"), &p, &p, &mut one);
                    one.insert(format!(".vlt/{name}"), "dir".into());
                } else {
                    one.insert(format!(".vlt/{name}"), "entry".into());
                }
                out.extend(one);
            }
        }
        if let Some(store) = store {
            snap_walk("store", store, store, &mut out);
        }
        Snapshot(out)
    }

    pub fn assert_same(&self, other: &Snapshot, what: &str) {
        self.compare(other, what, false);
    }

    /// [`Snapshot::assert_same`], except that vlt may add global-store
    /// entries of its own (it writes them lazily): only existing entries
    /// must be unchanged.
    pub fn assert_existing_unchanged(&self, other: &Snapshot, what: &str) {
        self.compare(other, what, true);
    }

    fn compare(&self, other: &Snapshot, what: &str, store_additions: bool) {
        if self == other {
            return;
        }
        let mut diff = Vec::new();
        for (k, v) in &self.0 {
            match other.0.get(k) {
                Some(w) if w == v => {}
                Some(w) => diff.push(format!("changed {k}: {v} -> {w}")),
                None => diff.push(format!("removed {k}")),
            }
        }
        for k in other.0.keys() {
            if !(self.0.contains_key(k) || store_additions && k.starts_with("store/")) {
                diff.push(format!("added {k}"));
            }
        }
        if diff.is_empty() {
            return;
        }
        panic!(
            "{what} touched entries it does not own:\n{}",
            diff.join("\n")
        );
    }
}

// ── the byte-stability oracle ─────────────────────────────────────────────

/// `vlt ci` (or the pre-0.0.0-19 locked install) leaves `vlt-lock.json`
/// byte-identical. `churn_shape` marks the one measured exception (rc.14
/// rewrites an alias-named `file:` dependency's outgoing peer-edge spec on
/// its first `ci`): there stability is asserted from the second run on.
pub fn assert_ci_byte_stable(leg: &Leg, proj: &Path, run: &VltRun, churn_shape: bool) {
    let before = lock_bytes(proj);
    let args = leg.locked_install_args();
    leg.vlt_ok_with(proj, &args, run);
    let after = lock_bytes(proj);
    if churn_shape && leg.version() == VltVersion::rc(14) && before != after {
        leg.vlt_ok_with(proj, &args, run);
        assert_eq!(
            lock_bytes(proj),
            after,
            "vlt {} churned vlt-lock.json on the second {args:?} too",
            leg.tc.raw
        );
        return;
    }
    assert_eq!(
        String::from_utf8_lossy(&after),
        String::from_utf8_lossy(&before),
        "vlt {} {args:?} changed vlt-lock.json",
        leg.tc.raw
    );
}

// ── git ───────────────────────────────────────────────────────────────────

pub fn git(cwd: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args([
            "-c",
            "user.email=e2e@example.invalid",
            "-c",
            "user.name=e2e",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .output()
        .expect("spawn git")
}

pub fn git_ok(cwd: &Path, args: &[&str]) -> String {
    let out = git(cwd, args);
    assert_ok(&out, &format!("git {}", args.join(" ")));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn has_git() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

// ── harness self-tests ────────────────────────────────────────────────────

#[test]
fn vlt_e2e_harness_orders_versions_and_eras() {
    let v = |s: &str| VltVersion::parse(s).unwrap();
    assert!(v("0.0.0-1") < v("0.0.0-11"));
    assert!(v("0.0.0-32") < v("1.0.0-rc.1"));
    assert!(v("1.0.0-rc.34") < v("1.0.1"));
    assert!(v("1.0.10") > v("1.0.8"));
    assert_eq!(v("1.0.0-rc.14").to_string(), "1.0.0-rc.14");
    assert_eq!(v("0.0.0-16").to_string(), "0.0.0-16");
    assert_eq!(v("1.2.0").to_string(), "1.2.0");
    for (raw, era) in [
        ("0.0.0-1", VltEra::A0),
        ("0.0.0-18", VltEra::A0),
        ("0.0.0-19", VltEra::A),
        ("1.0.0-rc.8", VltEra::A),
        ("1.0.0-rc.9", VltEra::B),
        ("1.0.0-rc.14", VltEra::B),
        ("1.0.0-rc.15", VltEra::C),
        ("1.0.0-rc.32", VltEra::C),
        ("1.0.0-rc.33", VltEra::D),
        ("1.0.7", VltEra::D),
        ("1.0.8", VltEra::E),
        ("1.1.1", VltEra::E),
        ("1.2.0", VltEra::F),
    ] {
        assert_eq!(VltEra::from_version(v(raw)), era, "{raw}");
    }
}

#[test]
fn vlt_e2e_harness_vlt_json_follows_the_era_table() {
    let r = "http://127.0.0.1:4873/";
    let v = |s: &str| VltVersion::parse(s).unwrap();
    let d = VltJson::default();
    assert_eq!(vlt_json(v("0.0.0-11"), r, &d), json!({ "registry": r }));
    assert_eq!(
        vlt_json(v("0.0.0-16"), r, &d),
        json!({ "config": { "registry": r }, "modifiers": {} })
    );
    assert_eq!(
        vlt_json(v("0.0.0-25"), r, &d),
        json!({ "config": { "registry": r } })
    );
    assert_eq!(
        vlt_json(v("1.0.0-rc.14"), r, &d),
        json!({ "config": { "registry": "https://registry.npmjs.org/" } })
    );
    assert_eq!(
        vlt_json(v("1.0.0-rc.30"), r, &d),
        json!({ "config": { "registry": r } })
    );
    assert_eq!(
        vlt_json(v("1.0.4"), r, &d),
        json!({ "config": { "registries": { "npm": r }, "registry": r } })
    );
    assert_eq!(
        vlt_json(v("1.2.0"), r, &d),
        json!({ "config": { "registries": { "npm": r } } })
    );
}

#[test]
fn vlt_e2e_harness_leg_lines_have_the_counted_shape() {
    let line = leg_line("1.2.0", "hosted", "fresh_ci", "ran");
    let parts: Vec<&str> = line.split(' ').collect();
    assert_eq!(parts.len(), 6, "{line}");
    assert_eq!(parts[0], "VLT-LEG");
    assert_eq!(parts[2], os_name());
    assert_eq!(parts[5], "ran");
}

#[test]
fn vlt_e2e_harness_decodes_dep_ids() {
    let d = |s: &str| decode_registry_id(s).map(|(r, n, v)| format!("{r}|{n}|{v}"));
    assert_eq!(
        d("~npm~left-pad@1.3.0").as_deref(),
        Some("npm|left-pad|1.3.0")
    );
    assert_eq!(
        d("~npm~@a+b@1.0.0~peer.2").as_deref(),
        Some("npm|@a/b|1.0.0")
    );
    assert_eq!(d("~npm~a__b@1.0.0").as_deref(), Some("npm|a_b|1.0.0"));
    assert_eq!(d("··ms@2.1.3").as_deref(), Some("|ms|2.1.3"));
    assert_eq!(
        d("·npm·@isaacs§string-locale-compare@1.1.0").as_deref(),
        Some("npm|@isaacs/string-locale-compare|1.1.0")
    );
    assert_eq!(
        d("~http_c++127.0.0.1_c4873+~x@1.0.0").as_deref(),
        Some("http://127.0.0.1:4873/|x|1.0.0")
    );
    assert_eq!(
        d("·http%3A§§127.0.0.1%3A4873§·x@1.0.0").as_deref(),
        Some("http://127.0.0.1:4873/|x|1.0.0")
    );
    assert_eq!(d("file~_d"), None);
    assert_eq!(d("··x@1%ZZ"), None);
}

#[test]
fn vlt_e2e_harness_tarballs_are_deterministic() {
    let mut files = BTreeMap::new();
    files.insert("index.js".to_string(), b"x".to_vec());
    files.insert("package.json".to_string(), b"{}".to_vec());
    let a = build_tgz(&files);
    assert_eq!(a, build_tgz(&files));
    assert_eq!(tgz_files(&a), files);
}

#[test]
fn vlt_e2e_harness_npx_shim_forwards_the_args_after_the_package() {
    let dir = std::env::temp_dir().join(format!("vlt-e2e-shim-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let argv = dir.join("argv.txt");
    let log = dir.join("npx.log");
    let fake = if cfg!(windows) {
        let fake = dir.join("socket.cmd");
        write(
            &fake,
            format!("@echo off\r\n>\"{}\" echo %*\r\n", argv.display()),
        );
        fake
    } else {
        let fake = dir.join("socket");
        write(
            &fake,
            format!("#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\n", argv.display()),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        fake
    };
    let bin = dir.join("bin");
    write_shims_for(&bin, Path::new("vlt.js"), &log, &fake);
    let npx = bin.join(if cfg!(windows) { "npx.cmd" } else { "npx" });
    let out = Command::new(npx)
        .args([
            "-y",
            "@socketsecurity/socket-patch",
            "apply",
            "--silent",
            "--ecosystems",
            "npm",
        ])
        .output()
        .unwrap();
    assert_ok(&out, "the npx shim");
    let args = "apply --silent --ecosystems npm";
    assert_eq!(std::fs::read_to_string(&argv).unwrap().trim(), args);
    assert_eq!(
        std::fs::read_to_string(&log).unwrap().trim(),
        format!("npx {args}")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
