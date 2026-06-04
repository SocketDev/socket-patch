// Pure decision logic for the guard's build script.
//
// This file is the single source of truth for *what* the guard does. It is
// both compiled as a module of the library (`mod logic;` in `lib.rs`, so the
// functions are unit-tested) and `include!`d verbatim by `build.rs` (a build
// script cannot depend on the very crate it builds, so sharing happens via
// `include!` rather than a normal import). Inner (`//!`) doc comments are
// deliberately avoided here because `include!` pastes this file mid-`build.rs`,
// where inner docs are illegal. Keep it free of any I/O so it stays trivially
// testable; `build.rs` performs the side effects.
//
// The guard has exactly ONE mode: fail-closed. It verifies the committed cargo
// patches match the manifest (`apply --check`); on drift it tries to heal
// (`apply`), then fails the build (the current build already compiled the stale
// copy) — so a build never silently uses stale/unpatched sources. There is no
// drift-tolerating `warn`/`off` mode: an unrecoverable state or a missing CLI
// fails the build (an unconfigured project with no root is simply not guarded).

/// What the guard should do, computed purely from environment values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// `SOCKET_PATCH_ROOT` is unset/empty → warn and do nothing this build.
    SkipRootUnset,
    /// Operate on `<root>` using `<bin>`.
    Run { root: String, bin: String },
}

/// Compute the plan from the `SOCKET_PATCH_ROOT` / `SOCKET_PATCH_BIN` values.
/// An unset *or empty* root skips; an unset/empty bin defaults to
/// `socket-patch` (resolved from `PATH`).
pub fn plan(root: Option<&str>, bin: Option<&str>) -> Plan {
    match root {
        Some(r) if !r.is_empty() => Plan::Run {
            root: r.to_string(),
            bin: match bin {
                Some(b) if !b.is_empty() => b.to_string(),
                _ => "socket-patch".to_string(),
            },
        },
        _ => Plan::SkipRootUnset,
    }
}

/// The `cargo:` directives that make this build script re-run only when the
/// dependency set (`Cargo.lock`) or patch set (`.socket/manifest.json`) under
/// `root` changes (plus the two env vars the guard reads).
pub fn rerun_keys(root: &str) -> Vec<String> {
    vec![
        "cargo:rerun-if-env-changed=SOCKET_PATCH_ROOT".to_string(),
        "cargo:rerun-if-env-changed=SOCKET_PATCH_BIN".to_string(),
        format!("cargo:rerun-if-changed={root}/Cargo.lock"),
        format!("cargo:rerun-if-changed={root}/.socket/manifest.json"),
    ]
}

/// Args for the read-only drift probe: `apply --check ...`. Exit 0 = the
/// committed patched copies match the manifest (cargo is compiling correct
/// patches); non-zero = drift (stale copy, or a patch that silently fell back
/// to an unpatched version). Read-only, lock-free, offline.
pub fn check_args(root: &str) -> Vec<String> {
    vec![
        "apply".to_string(),
        "--check".to_string(),
        "--offline".to_string(),
        "--ecosystems".to_string(),
        "cargo".to_string(),
        "--cwd".to_string(),
        root.to_string(),
    ]
}

/// Args for the heal: a real `apply` that regenerates the copies to match the
/// manifest. `--offline`: cargo already downloaded the sources during
/// resolution, and the patch artifacts are committed under `.socket/`.
pub fn apply_args(root: &str) -> Vec<String> {
    vec![
        "apply".to_string(),
        "--offline".to_string(),
        "--ecosystems".to_string(),
        "cargo".to_string(),
        "--cwd".to_string(),
        root.to_string(),
    ]
}

/// Outcome of running the read-only `apply --check` probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// `apply --check` exited 0: committed patches are in sync — cargo compiled
    /// correct, patched sources this build.
    InSync,
    /// `apply --check` exited non-zero: the committed copies cargo is compiling
    /// are stale, or a patched dependency resolved to an unpatched version.
    Drift,
    /// The probe couldn't run at all (e.g. the binary isn't on `PATH`); carries
    /// the OS error text.
    ProbeError(String),
}

/// What `build.rs` should do after the initial probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Build proceeds (correct patches were compiled).
    Proceed,
    /// Run `apply` to heal, then re-probe (see [`fail_message_after_heal`]).
    Heal,
    /// Panic — fail the build (fail-closed).
    Fail(String),
}

/// Decide from the initial `apply --check`: in sync → proceed; drift → heal;
/// the probe couldn't run → fail-closed (the CLI is required).
pub fn decide_initial(probe: &Probe) -> Action {
    match probe {
        Probe::InSync => Action::Proceed,
        Probe::Drift => Action::Heal,
        Probe::ProbeError(err) => Action::Fail(probe_error_message(err)),
    }
}

/// The panic message after a heal + re-probe. The build always fails here (the
/// current build already compiled the stale copy); the message differs by
/// whether the heal reconciled the state:
/// * re-probe in sync → the heal worked → "regenerated, re-run the build";
/// * re-probe still drift → unrecoverable (e.g. a patched dep resolved to an
///   unpatched version, or corrupt/missing data) → tell the user to inspect;
/// * re-probe errored → the CLI stopped working mid-heal.
pub fn fail_message_after_heal(reprobe: &Probe, detail: &str) -> String {
    match reprobe {
        Probe::InSync => "socket-patch: cargo patches were out of date and have been \
             regenerated under .socket/cargo-patches/ to match .socket/manifest.json. \
             Re-run the build to compile against the up-to-date patches (this build was \
             failed to avoid using stale patches)."
            .to_string(),
        Probe::Drift => {
            let mut msg = "socket-patch: cargo patches are out of sync and could NOT be \
                 reconciled by `apply` — a patched dependency may have resolved to a version \
                 the manifest does not patch, or the patch data/manifest is corrupt or \
                 missing. Run `socket-patch apply --ecosystems cargo` and inspect."
                .to_string();
            let detail = detail.trim();
            if !detail.is_empty() {
                msg.push_str("\n  detail: ");
                msg.push_str(detail);
            }
            msg
        }
        Probe::ProbeError(err) => probe_error_message(err),
    }
}

fn probe_error_message(err: &str) -> String {
    format!(
        "socket-patch: could not run `apply --check` ({err}); the socket-patch CLI is \
         required to verify cargo patches are in sync. Install it or set SOCKET_PATCH_BIN \
         to its path."
    )
}
