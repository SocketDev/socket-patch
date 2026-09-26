//! Real-vlt copy-on-write safety (suite `safety`, DESIGN §5.4, §8.3).
//!
//! vlt 1.2.0 keeps a global content store (`$XDG_CACHE_HOME/vlt/store/v1`)
//! and, with `store-linker=hardlink` (the Linux `auto` default), hardlinks
//! every project's package files to it. An in-place write would poison
//! every project on the machine. Two projects share one XDG cache here;
//! every socket-patch write path in p1 (agent apply and rollback, the
//! hosted heal, the vendored local build, `vendor --revert`, `repair`)
//! must leave p2's bytes and inodes and the store untouched.
//!
//! `SOCKET_PATCH_VLT_E2E_STORE_LINKER` ∈ {auto, hardlink, copy, unpack}
//! selects the linker (unset = auto); `SOCKET_PATCH_VLT_E2E_CACHE_ROOT`
//! moves the cache to another filesystem (EXDEV → copy). Each leg is
//! `vlt_pinned_matrix_safety_<leg>` and prints one `VLT-LEG` line.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[path = "vlt_e2e_common/mod.rs"]
mod vlt_e2e_common;

use vlt_e2e_common::fixture::*;
use vlt_e2e_common::*;

const SUITE: &str = "safety";

/// The linker vlt uses: the knob, else `auto` (hardlink on Linux, unpack
/// elsewhere).
fn effective_linker() -> String {
    match store_linker().as_deref() {
        Some("auto") | None => {
            if cfg!(target_os = "linux") {
                "hardlink".into()
            } else {
                "unpack".into()
            }
        }
        Some(other) => other.into(),
    }
}

fn hardlinks() -> bool {
    effective_linker() == "hardlink" && cache_root_knob().is_none()
}

fn safety_leg(name: &'static str) -> Option<Leg> {
    let leg = Leg::start(SUITE, name)?;
    if !leg.at_least(STORE_LINKER_FROM) {
        leg.skip("no-global-store");
        return None;
    }
    Some(leg)
}

#[cfg(unix)]
fn nlink(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(p).unwrap().nlink()
}

#[cfg(windows)]
fn nlink(p: &Path) -> u64 {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let f = std::fs::File::open(p).unwrap();
    // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid value, and
    // the handle stays open for the call.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, &mut info) };
    assert_ne!(ok, 0, "GetFileInformationByHandle({})", p.display());
    u64::from(info.nNumberOfLinks)
}

#[cfg(unix)]
fn ino(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(p).unwrap().ino()
}

#[cfg(windows)]
fn ino(p: &Path) -> u64 {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let f = std::fs::File::open(p).unwrap();
    // SAFETY: as in `nlink`.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, &mut info) };
    assert_ne!(ok, 0);
    (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)
}

/// Two projects on one registry and one XDG cache.
struct Pair {
    fx: Fixture,
    p2: PathBuf,
}

impl Pair {
    async fn build(leg: Leg, shape: Shape) -> Pair {
        let fx = Fixture::build(leg, shape).await;
        if effective_linker() != "unpack" {
            wait_for_store(&fx);
        }
        remove_tree(&fx.proj);
        fx.vlt_ok(&fx.proj, &["install"]);
        let p2 = fx.leg.dir("p2");
        for f in ["package.json", "vlt.json", VLT_LOCK] {
            std::fs::copy(fx.proj.join(f), p2.join(f)).unwrap();
        }
        fx.vlt_ok(&p2, &["install"]);
        Pair { fx, p2 }
    }

    fn target_file(&self, dir: &Path) -> PathBuf {
        let t = self.fx.t();
        importer_dir(dir, "", &t.name)
            .join(&t.file)
            .canonicalize()
            .unwrap()
    }

    /// The linker precondition: shared inodes for hardlink, private ones
    /// for copy / unpack / a cache on another filesystem.
    fn assert_precondition(&self) {
        let a = self.target_file(&self.fx.proj);
        let b = self.target_file(&self.p2);
        if hardlinks() {
            assert!(
                nlink(&a) >= 2,
                "hardlinked: nlink {} for {}",
                nlink(&a),
                a.display()
            );
            assert_eq!(ino(&a), ino(&b), "p1 and p2 share the store inode");
        } else {
            assert_eq!(nlink(&a), 1, "{} links a private copy", effective_linker());
        }
    }

    /// p2's bytes and inodes plus the store, for [`Pair::assert_untouched`].
    fn witness(&self) -> (BTreeMap<String, Vec<u8>>, u64, Snapshot) {
        let b = self.target_file(&self.p2);
        let store = self.fx.leg.global_store("default");
        (
            package_files(
                &importer_dir(&self.p2, "", &self.fx.t().name)
                    .canonicalize()
                    .unwrap(),
            ),
            ino(&b),
            Snapshot::take(&self.p2, &[], Some(&store)),
        )
    }

    fn assert_untouched(&self, before: &(BTreeMap<String, Vec<u8>>, u64, Snapshot), what: &str) {
        let now = self.witness();
        assert_eq!(now.0, before.0, "{what}: p2's bytes changed");
        assert_eq!(now.1, before.1, "{what}: p2's inode changed");
        before.2.assert_existing_unchanged(&now.2, what);
        assert_eq!(
            state(&self.p2, self.fx.t()),
            State::Pristine,
            "{what}: p2 pristine"
        );
    }
}

fn wait_for_store(fx: &Fixture) {
    let store = fx.leg.global_store("default");
    for _ in 0..200 {
        if std::fs::read_dir(&store)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("vlt wrote no global store under {}", store.display());
}

fn agent(dir: &Path, cmd: &str, extra: &[&str]) -> SocketOut {
    let cwd = dir.to_str().unwrap().to_string();
    let mut args = vec![cmd, "--yes", "--offline", "--cwd", &cwd];
    args.extend_from_slice(extra);
    socket(dir, &args, &[])
}

/// The CoW proof for agent apply: p1's copy is patched through a new
/// private inode, p2 and the store are untouched.
fn apply_in_p1(pair: &Pair) {
    let fx = &pair.fx;
    stage_manifest(&fx.proj, &[fx.t()]);
    let before = pair.witness();
    let ino_before = ino(&pair.target_file(&fx.proj));
    let out = agent(&fx.proj, "apply", &["--json"]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let a = pair.target_file(&fx.proj);
    assert_eq!(nlink(&a), 1, "the patched file is a private inode");
    if hardlinks() {
        assert_ne!(ino(&a), ino_before, "rename-over, never an in-place write");
    }
    pair.assert_untouched(&before, "agent apply");
}

// ── linker legs ───────────────────────────────────────────────────────────

/// Linux `auto` (hardlink): the default-flip canary (nlink ≥ 2 after the
/// second install), apply CoW, p2 reinstalls pristine, `vlt install <x>`
/// keeps the patch, and `vlt ci` restores pristine bytes and re-applies
/// through the setup hook.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_linux_auto() {
    let Some(leg) = safety_leg("linux_auto") else {
        return;
    };
    if !cfg!(target_os = "linux")
        || !matches!(store_linker().as_deref(), None | Some("auto"))
        || cache_root_knob().is_some()
    {
        return leg.skip("not-linux-auto");
    }
    linker_sequence(leg).await;
}

/// `store-linker=hardlink` on every OS: the same sequence.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_explicit_hardlink() {
    let Some(leg) = safety_leg("explicit_hardlink") else {
        return;
    };
    if store_linker().as_deref() != Some("hardlink") || cache_root_knob().is_some() {
        return leg.skip("store-linker-not-hardlink");
    }
    linker_sequence(leg).await;
}

/// `store-linker=copy` / `unpack`, or the unpack `auto` of macOS and
/// Windows: private copies (nlink == 1), and apply stays CoW.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_private_copies() {
    let Some(leg) = safety_leg("private_copies") else {
        return;
    };
    if hardlinks() || cache_root_knob().is_some() {
        return leg.skip("store-linker-hardlinks");
    }
    linker_sequence(leg).await;
}

/// The cache on another filesystem (`SOCKET_PATCH_VLT_E2E_CACHE_ROOT`,
/// e.g. `/dev/shm`): the hardlink falls back to a copy (EXDEV), which
/// `NODE_DEBUG=vlt` logs, and apply stays CoW.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_cross_device_cache() {
    let Some(leg) = safety_leg("cross_device_cache") else {
        return;
    };
    if cache_root_knob().is_none() {
        return leg.skip("no-cache-root");
    }
    let pair = Pair::build(leg, Shape::with_bystander().warm()).await;
    let co = pair.fx.checkout("exdev");
    let out = pair.fx.leg.vlt_with(
        &co,
        &["install"],
        &VltRun::default().with_env("NODE_DEBUG", "vlt"),
    );
    assert_ok(&out, "NODE_DEBUG install");
    assert!(
        out_text(&out).contains("EXDEV"),
        "the EXDEV fallback is logged: {}",
        out_text(&out)
    );
    pair.assert_precondition();
    apply_in_p1(&pair);
    pair.fx.leg.ran();
}

async fn linker_sequence(leg: Leg) {
    let mut shape = Shape::with_bystander().warm();
    shape.pins.push(SCOPED);
    let pair = Pair::build(leg, shape).await;
    let fx = &pair.fx;
    pair.assert_precondition();
    apply_in_p1(&pair);
    remove_tree(&pair.p2);
    fx.vlt_ok(&pair.p2, &["install"]);
    assert_eq!(
        state(&pair.p2, fx.t()),
        State::Pristine,
        "p2 reinstalls pristine"
    );
    fx.vlt_ok(
        &fx.proj,
        &["install", "@isaacs/string-locale-compare@1.1.0"],
    );
    assert_eq!(
        state(&fx.proj, fx.t()),
        State::Patched,
        "vlt install <x> keeps it"
    );
    let out = agent(&fx.proj, "setup", &["--json"]);
    assert_eq!(out.code, 0, "{out}");
    let before = pair.witness();
    let run = VltRun::default().with_shims();
    fx.leg.vlt_ok_with(&fx.proj, &["ci"], &run);
    assert!(
        !fx.leg.npx_log().is_empty(),
        "the postinstall hook ran through the npx shim"
    );
    assert_eq!(
        state(&fx.proj, fx.t()),
        State::Patched,
        "vlt ci + the hook re-apply"
    );
    pair.assert_untouched(&before, "vlt ci + hook");
    pair.fx.leg.ran();
}

// ── every write path on the shared store (T16) ────────────────────────────

async fn shared_pair(leg: Leg, shape: Shape) -> Pair {
    let pair = Pair::build(leg, shape).await;
    pair.assert_precondition();
    pair
}

/// Agent rollback, including onto a hardlinked pristine inode after `vlt
/// ci`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_agent_rollback() {
    let Some(leg) = safety_leg("agent_rollback") else {
        return;
    };
    let pair = shared_pair(leg, Shape::with_bystander().warm()).await;
    let fx = &pair.fx;
    apply_in_p1(&pair);
    let before = pair.witness();
    let out = agent(&fx.proj, "rollback", &["--json"]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Pristine);
    pair.assert_untouched(&before, "agent rollback");
    stage_manifest(&fx.proj, &[fx.t()]);
    fx.vlt_ok(&fx.proj, &["ci"]);
    pair.assert_precondition();
    let out = agent(&fx.proj, "rollback", &["--json"]);
    assert!(out.code == 0 || out.code == 1, "{out}");
    assert_eq!(state(&fx.proj, fx.t()), State::Pristine);
    pair.assert_untouched(&before, "rollback onto the hardlinked pristine inode");
    pair.fx.leg.ran();
}

/// Agent apply fans out to every store copy of a peer-resolved package.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_peer_fanout() {
    let Some(leg) = safety_leg("peer_fanout") else {
        return;
    };
    let usx = ("use-sync-external-store", "1.2.0");
    let shape = Shape {
        deps: vec![usx, ("react", "18.2.0")],
        pins: vec![
            usx,
            ("react", "18.2.0"),
            ("loose-envify", "1.4.0"),
            ("js-tokens", "4.0.0"),
        ],
        targets: vec![(usx.0, usx.1, UUID_USX, "index.js")],
        warm: true,
        ..Shape::left_pad()
    };
    let pair = shared_pair(leg, shape).await;
    let fx = &pair.fx;
    let ids = fx.store_ids(fx.t());
    assert!(ids.iter().all(|id| id.contains("~peer.")), "{ids:?}");
    apply_in_p1(&pair);
    for id in &ids {
        let dir = store_pkg(&fx.proj, id, &fx.t().name);
        assert_eq!(state_at(&dir, fx.t()), State::Patched, "{id}");
    }
    pair.fx.leg.ran();
}

/// The hosted heal deletes p1's hardlinked `.vlt/<DepID>`, never the store.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_hosted_heal() {
    let Some(leg) = safety_leg("hosted_heal") else {
        return;
    };
    let pair = shared_pair(leg, Shape::with_bystander().warm()).await;
    let fx = &pair.fx;
    let before = pair.witness();
    let ids = fx.store_ids(fx.t());
    let doc = fx.scan(&[]);
    fx.assert_advisory(&doc, &advisory_invalidated(ids.len()));
    for id in &ids {
        assert!(!store_entry(&fx.proj, id).exists());
    }
    pair.assert_untouched(&before, "the hosted heal");
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    pair.assert_untouched(&before, "the patched reinstall");
    pair.fx.leg.ran();
}

/// The vendored local build copies p1's installed (hardlinked) package.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_vendored_build() {
    let Some(leg) = safety_leg("vendored_build") else {
        return;
    };
    let pair = shared_pair(leg, Shape::with_bystander().warm()).await;
    let fx = &pair.fx;
    let before = pair.witness();
    let out = socket_api(
        &fx.proj,
        &fx.svc,
        &["scan", "--mode", "vendored"],
        &["--vendor-source", "build"],
    );
    assert_eq!(out.code, 0, "{out}");
    pair.assert_untouched(&before, "the vendored build");
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    pair.assert_untouched(&before, "installing the vendored payload");
    pair.fx.leg.ran();
}

/// `vendor --revert` and `repair` on the shared store.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_vendor_revert_and_repair() {
    let Some(leg) = safety_leg("vendor_revert_and_repair") else {
        return;
    };
    let pair = shared_pair(leg, Shape::with_bystander().warm()).await;
    let fx = &pair.fx;
    let out = socket_api(
        &fx.proj,
        &fx.svc,
        &["scan", "--mode", "vendored"],
        &["--vendor-source", "build"],
    );
    assert_eq!(out.code, 0, "{out}");
    fx.vlt_ok(&fx.proj, &["install"]);
    let before = pair.witness();
    let out = socket_api(&fx.proj, &fx.svc, &["repair"], &[]);
    assert_eq!(out.code, 0, "{out}");
    pair.assert_untouched(&before, "repair");
    let cwd = fx.proj.to_str().unwrap().to_string();
    let out = socket(
        &fx.proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--yes",
            "--offline",
            "--cwd",
            &cwd,
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{out}");
    pair.assert_untouched(&before, "vendor --revert");
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Pristine);
    pair.assert_untouched(&before, "the registry reinstall");
    pair.fx.leg.ran();
}

/// Human `apply` prints the vlt layout note.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_safety_layout_note() {
    let Some(leg) = safety_leg("layout_note") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    stage_manifest(&fx.proj, &[fx.t()]);
    let out = agent(&fx.proj, "apply", &[]);
    assert_eq!(out.code, 0, "{out}");
    let text = format!("{}{}", out.stdout, out.stderr);
    assert!(
        text.contains("Note: vlt layout detected. Copy-on-write keeps vlt's shared package store"),
        "{text}"
    );
    fx.leg.ran();
}
