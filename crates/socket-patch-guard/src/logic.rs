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
/// `root` changes (plus the env vars).
pub fn rerun_keys(root: &str) -> Vec<String> {
    vec![
        "cargo:rerun-if-env-changed=SOCKET_PATCH_ROOT".to_string(),
        "cargo:rerun-if-env-changed=SOCKET_PATCH_BIN".to_string(),
        "cargo:rerun-if-env-changed=SOCKET_PATCH_GUARD".to_string(),
        format!("cargo:rerun-if-changed={root}/Cargo.lock"),
        format!("cargo:rerun-if-changed={root}/.socket/manifest.json"),
    ]
}

/// Args for the read-only drift probe: `apply --check ...`. Exit 0 = the
/// committed patched copies match the manifest (cargo is compiling correct
/// patches); non-zero = drift (stale copy or a patch that silently fell back
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

/// Args for the (warn-mode) heal: a real `apply` that regenerates the copies.
/// `--offline`: cargo already downloaded the sources during resolution, and
/// the patch artifacts are committed under `.socket/`.
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

/// How the guard reacts to drift / a missing binary. From `SOCKET_PATCH_GUARD`:
/// unset/other = `Error` (fail-closed, the default), `warn` = heal + continue
/// (accept a one-build lag), `off` = skip the guard entirely (loud).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardMode {
    Error,
    Warn,
    Off,
}

pub fn guard_mode(env: Option<&str>) -> GuardMode {
    match env {
        Some("off") => GuardMode::Off,
        Some("warn") => GuardMode::Warn,
        _ => GuardMode::Error,
    }
}

/// Outcome of running the read-only `apply --check` probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// `apply --check` exited 0: committed patches are in sync — cargo compiled
    /// correct, patched sources this build.
    InSync,
    /// `apply --check` exited non-zero: the committed copies cargo is compiling
    /// are stale, or a patched dependency resolved to an unpatched version.
    Drift,
    /// The probe binary could not be spawned at all (carries the OS error).
    ProbeFailed(String),
}

/// What `build.rs` should do after the probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Build proceeds (correct patches were compiled).
    Proceed,
    /// Regenerate via `apply`, emit `cargo:warning`, continue (warn mode).
    HealAndWarn(String),
    /// `cargo:warning` then continue (a softened skip).
    Warn(String),
    /// Panic — fail the build. Does NOT heal (no working-tree mutation in a
    /// failed build).
    Fail(String),
}

/// Map the probe outcome + mode to the build-script action.
///
/// Fail-closed by design: in the default (`Error`) mode a drift FAILS the build
/// so a stale/unpatched artifact is never produced. `Warn` heals and continues
/// (the pre-fix lazy behavior, with a one-build lag). A binary that can't be
/// spawned fails in `Error` and warns in `Warn`. (`Off` is handled by the
/// caller before probing; the catch-all keeps this total.)
pub fn decide(check: &CheckOutcome, mode: GuardMode) -> Action {
    match check {
        CheckOutcome::InSync => Action::Proceed,
        CheckOutcome::Drift => match mode {
            GuardMode::Error => Action::Fail(
                "socket-patch: the committed cargo patches under .socket/cargo-patches/ are \
                 out of sync with .socket/manifest.json (a copy is stale, or a patched \
                 dependency resolved to an unpatched version). This build was FAILED to \
                 avoid compiling against stale/unpatched sources. Run \
                 `socket-patch apply --ecosystems cargo`, commit the regenerated \
                 .socket/cargo-patches/ + .cargo/config.toml, and rebuild. (Set \
                 SOCKET_PATCH_GUARD=warn to heal-and-continue with a one-build lag.)"
                    .to_string(),
            ),
            GuardMode::Warn => Action::HealAndWarn(
                "socket-patch: cargo patches were out of sync and have been regenerated. \
                 This build may have compiled against stale patches — re-run the build to \
                 pick up the regenerated sources."
                    .to_string(),
            ),
            GuardMode::Off => Action::Proceed,
        },
        CheckOutcome::ProbeFailed(err) => match mode {
            GuardMode::Error => Action::Fail(format!(
                "socket-patch: could not run `apply --check` ({err}); it is required to \
                 verify cargo patches are in sync. Install the `socket-patch` binary, set \
                 SOCKET_PATCH_BIN to its path, or set SOCKET_PATCH_GUARD=warn to bypass."
            )),
            GuardMode::Warn => Action::Warn(format!(
                "socket-patch guard skipped: could not run the patch check ({err})"
            )),
            GuardMode::Off => Action::Proceed,
        },
    }
}
