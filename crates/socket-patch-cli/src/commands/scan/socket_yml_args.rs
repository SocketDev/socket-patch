//! `scan`'s `socket.yml` patch-policy flags.

use clap::Args;
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
}
