//! `scan`'s patch-policy flags: the `socket.yml` ones, and the internal
//! selection filter (`socket_patch_core::policy::filter`).

use std::path::PathBuf;

use clap::Args;
use socket_patch_core::policy::filter::SelectionFilter;
use socket_patch_core::policy::{parse_min_severity, OverrideSource, PolicyOverrides};

/// Env binding of `--min-severity`, read by [`SocketYmlArgs::overrides`]
/// (not by clap) so the policy can say which layer set the floor.
pub const MIN_SEVERITY_ENV: &str = "SOCKET_MIN_SEVERITY";

#[derive(Args, Clone, Debug, Default)]
pub struct SocketYmlArgs {
    /// Ignore the repository's socket.yml patch policy (its `patches`
    /// block and `projectIgnorePaths`) for this run. The built-in
    /// test/fixture directory ignores still apply
    #[arg(
        long = "no-socket-yml",
        env = "SOCKET_NO_SOCKET_YML",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub no_socket_yml: bool,

    /// Only patch packages whose patch fixes an advisory of at least this
    /// severity: critical, high, medium (or moderate), low, or none for no
    /// floor. Overrides `patches.minSeverity` in socket.yml. Patches of
    /// unknown severity are skipped whenever a floor is set
    /// [env: SOCKET_MIN_SEVERITY]
    #[arg(long = "min-severity", value_name = "SEVERITY", value_parser = min_severity_value)]
    pub min_severity: Option<String>,

    /// Narrow the run with a selection filter: a JSON file of paths,
    /// packages and advisories to skip, and reachability findings, so
    /// only the patches that fix a reachable (or unknown) vulnerability
    /// are applied
    //
    // INTERNAL (hidden from `--help`): the interface of Socket's own
    // remediation tooling. The file format and its semantics are
    // documented on `socket_patch_core::policy::filter`.
    #[arg(
        long = "selection-filter",
        value_name = "FILE",
        env = "SOCKET_SELECTION_FILTER",
        hide = true
    )]
    pub selection_filter: Option<PathBuf>,
}

fn min_severity_value(value: &str) -> Result<String, String> {
    parse_min_severity(value).map(|_| value.to_string())
}

impl SocketYmlArgs {
    /// The trusted overrides: `--min-severity` beats `SOCKET_MIN_SEVERITY`
    /// (an empty value is unset). `Err` is a usage error (exit 2).
    pub fn overrides(&self) -> Result<PolicyOverrides, String> {
        let min_severity = match self.min_severity.as_deref() {
            Some(flag) => Some((
                parse_min_severity(flag).map_err(|e| format!("--min-severity: {e}"))?,
                OverrideSource::Flag,
            )),
            None => match std::env::var(MIN_SEVERITY_ENV) {
                Ok(value) if !value.trim().is_empty() => Some((
                    parse_min_severity(&value).map_err(|e| format!("{MIN_SEVERITY_ENV}: {e}"))?,
                    OverrideSource::Env,
                )),
                _ => None,
            },
        };
        Ok(PolicyOverrides {
            bypass: self.no_socket_yml,
            min_severity,
        })
    }

    /// Read `--selection-filter` (a relative path is relative to the
    /// process's working directory, not `--cwd`, like `--vex`; an empty env
    /// value is unset before clap parses, see `LOCAL_ARG_ENV_VARS`). `Err` is the
    /// message of a file that cannot be honored: the run fails before any
    /// request or write (`filter_invalid`, exit 2).
    pub fn load_selection_filter(&self) -> Result<Option<SelectionFilter>, String> {
        let Some(path) = self.selection_filter.as_deref() else {
            return Ok(None);
        };
        // The path may have come from the flag or from its env var.
        SelectionFilter::read(path).map(Some).map_err(|e| {
            let shown = socket_patch_core::policy::strip_unsafe(&path.display().to_string());
            format!("selection filter {shown}: {e}")
        })
    }
}
