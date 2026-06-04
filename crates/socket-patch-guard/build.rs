//! Build-time guard. Runs `socket-patch apply --check` to verify the committed
//! cargo patches are in sync with `.socket/manifest.json`, and FAILS the build
//! (fail-closed) when they are not — so a `cargo build` can never silently
//! compile against stale or unpatched sources. `SOCKET_PATCH_GUARD=warn` heals
//! and continues with a one-build lag; `=off` disables the guard (loudly).
//!
//! A build script cannot depend on the crate it builds, so the pure decision
//! logic is `include!`d from `src/logic.rs` (the same file `lib.rs` exposes as
//! a module for unit tests). This file holds only the I/O + side effects.

include!("src/logic.rs");

fn main() {
    let root = std::env::var("SOCKET_PATCH_ROOT").ok();
    let bin = std::env::var("SOCKET_PATCH_BIN").ok();
    let guard_env = std::env::var("SOCKET_PATCH_GUARD").ok();

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

    let mode = guard_mode(guard_env.as_deref());
    if mode == GuardMode::Off {
        println!(
            "cargo:warning=socket-patch guard DISABLED (SOCKET_PATCH_GUARD=off); \
             cargo patches are NOT verified for this build"
        );
        return;
    }

    // Read-only drift probe. Exit 0 ⇒ the committed copies cargo is compiling
    // match the manifest (correct patches); non-zero ⇒ drift.
    let check = match std::process::Command::new(&bin)
        .args(check_args(&root))
        .status()
    {
        Ok(status) if status.success() => CheckOutcome::InSync,
        Ok(_) => CheckOutcome::Drift,
        Err(e) => CheckOutcome::ProbeFailed(e.to_string()),
    };

    match decide(&check, mode) {
        Action::Proceed => {}
        Action::Warn(msg) => println!("cargo:warning={msg}"),
        Action::Fail(msg) => panic!("{msg}"),
        Action::HealAndWarn(msg) => {
            // Warn mode only: regenerate so the *next* build is clean. Strict
            // mode deliberately does NOT heal (no tree mutation in a failed
            // build); the user runs `socket-patch apply` and rebuilds.
            let _ = std::process::Command::new(&bin)
                .args(apply_args(&root))
                .status();
            println!("cargo:warning={msg}");
        }
    }
}
