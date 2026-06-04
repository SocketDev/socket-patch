//! Build-time guard (single fail-closed mode). Runs `socket-patch apply --check`
//! to verify the committed cargo patches match `.socket/manifest.json`. In sync
//! → the build proceeds. On drift → it heals (`apply`) and then FAILS this build
//! (the current build already compiled the stale copy), so a `cargo build` can
//! never silently use stale/unpatched sources; the re-run is clean. If the heal
//! can't reconcile (a patched dep resolved to an unpatched version, or the data
//! is corrupt/missing) or the CLI can't be run, it fails-closed with diagnostics.
//! There is no drift-tolerating `warn`/`off` mode (an unconfigured project with
//! no `SOCKET_PATCH_ROOT` is simply not guarded yet — see `plan`).
//!
//! A build script cannot depend on the crate it builds, so the pure decision
//! logic is `include!`d from `src/logic.rs` (the same file `lib.rs` exposes as a
//! module for unit tests). This file holds only the I/O + side effects.

include!("src/logic.rs");

use std::process::Command;

/// Run `apply --check` and classify the result. `detail` captures the command's
/// output (used in the unrecoverable-drift message).
fn probe(bin: &str, root: &str) -> (Probe, String) {
    match Command::new(bin).args(check_args(root)).output() {
        Ok(out) if out.status.success() => (Probe::InSync, String::new()),
        Ok(out) => {
            let mut detail = String::from_utf8_lossy(&out.stdout).to_string();
            detail.push_str(&String::from_utf8_lossy(&out.stderr));
            (Probe::Drift, detail)
        }
        Err(e) => (Probe::ProbeError(e.to_string()), String::new()),
    }
}

fn main() {
    let root = std::env::var("SOCKET_PATCH_ROOT").ok();
    let bin = std::env::var("SOCKET_PATCH_BIN").ok();

    let (root, bin) = match plan(root.as_deref(), bin.as_deref()) {
        Plan::SkipRootUnset => {
            // Re-run if the var appears later (e.g. after `socket-patch setup`).
            println!("cargo:rerun-if-env-changed=SOCKET_PATCH_ROOT");
            println!(
                "cargo:warning=socket-patch: SOCKET_PATCH_ROOT is unset; \
                 run `socket-patch setup` to enable the cargo patch guard"
            );
            return;
        }
        Plan::Run { root, bin } => (root, bin),
    };

    for key in rerun_keys(&root) {
        println!("{key}");
    }

    let (probe1, _) = probe(&bin, &root);
    match decide_initial(&probe1) {
        Action::Proceed => {}
        Action::Fail(msg) => panic!("{msg}"),
        Action::Heal => {
            // Heal so the re-run is clean, then re-probe to distinguish a
            // recoverable stale copy from an unrecoverable state.
            let _ = Command::new(&bin).args(apply_args(&root)).status();
            let (reprobe, detail) = probe(&bin, &root);
            panic!("{}", fail_message_after_heal(&reprobe, &detail));
        }
    }
}
