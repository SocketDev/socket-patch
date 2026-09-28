//! `scan --max-new-patches` (work item B of the staged-rollout design,
//! `docs/design/staged-rollout.md` §5).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Args;
use socket_patch_core::rollout::{resolve_max_new, MaxNew};

/// The env binding of `--max-new-patches`. Read by [`RolloutArgs::resolve`]
/// rather than clap's `env =`, because the rollout block reports whether
/// the value came from the flag or the environment.
pub const MAX_NEW_PATCHES_ENV: &str = "SOCKET_MAX_NEW_PATCHES";

/// A parsed `--max-new-patches` value; `None` is `none` (no cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxNewPatches(pub Option<u32>);

/// `N` (0..=4294967295) or `none`, case-insensitive.
pub fn parse_max_new_patches(s: &str) -> Result<MaxNewPatches, String> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("none") {
        return Ok(MaxNewPatches(None));
    }
    s.parse::<u32>()
        .map(|n| MaxNewPatches(Some(n)))
        .map_err(|_| format!("`{s}` is not a number of patches (0 to 4294967295) or `none`"))
}

#[derive(Args, Clone, Default)]
pub struct RolloutArgs {
    /// Add at most N patches to packages that have none yet, most severe
    /// first; the rest are deferred to the next scan. Upgrades of patched
    /// packages are not capped. `none` lifts a cap set in socket.yml
    #[arg(
        long = "max-new-patches",
        value_name = "N|none",
        value_parser = parse_max_new_patches
    )]
    pub max_new_patches: Option<MaxNewPatches>,

    /// The budget shared by the project directories of one invocation.
    #[arg(skip)]
    pub(crate) carry: Option<RolloutCarry>,
}

impl RolloutArgs {
    /// The configured cap: the flag, then `env` (the
    /// [`MAX_NEW_PATCHES_ENV`] value; empty is unset), then the socket.yml
    /// value, then unlimited. A malformed env value is a usage error.
    pub fn resolve(&self, env: Option<&str>, file: Option<u32>) -> Result<MaxNew, String> {
        let env = match env.filter(|v| !v.is_empty()) {
            Some(raw) => Some(
                parse_max_new_patches(raw)
                    .map_err(|e| format!("{MAX_NEW_PATCHES_ENV}: {e}"))?
                    .0,
            ),
            None => None,
        };
        Ok(resolve_max_new(
            self.max_new_patches.map(|v| v.0),
            env,
            file,
            None,
        ))
    }

    /// [`Self::resolve`] against the process environment.
    pub fn resolve_from_env(&self, file: Option<u32>) -> Result<MaxNew, String> {
        let env = std::env::var(MAX_NEW_PATCHES_ENV).ok();
        self.resolve(env.as_deref(), file)
    }
}

/// What one invocation's project directories share: the cap as configured,
/// the budget left, and the base purls already admitted (admitted free in
/// later directories).
#[derive(Debug)]
pub(crate) struct Carry {
    pub(crate) configured: MaxNew,
    pub(crate) remaining: Option<u32>,
    pub(crate) admitted: BTreeSet<String>,
    /// The directory the project paths are relative to.
    pub(crate) root: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct RolloutCarry(pub(crate) Arc<Mutex<Carry>>);

impl RolloutCarry {
    pub(crate) fn new(configured: MaxNew, root: PathBuf) -> Self {
        RolloutCarry(Arc::new(Mutex::new(Carry {
            configured,
            remaining: configured.value,
            admitted: BTreeSet::new(),
            root,
        })))
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Carry> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::rollout::MaxNewSource;

    #[test]
    fn parses_numbers_and_none() {
        assert_eq!(parse_max_new_patches("5"), Ok(MaxNewPatches(Some(5))));
        assert_eq!(parse_max_new_patches("0"), Ok(MaxNewPatches(Some(0))));
        assert_eq!(
            parse_max_new_patches("4294967295"),
            Ok(MaxNewPatches(Some(u32::MAX)))
        );
        assert_eq!(parse_max_new_patches("NONE"), Ok(MaxNewPatches(None)));
        for bad in ["", "-1", "4294967296", "five", "1.5", "all"] {
            assert!(parse_max_new_patches(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn flag_beats_env_beats_file() {
        let flag = RolloutArgs {
            max_new_patches: Some(MaxNewPatches(Some(1))),
            carry: None,
        };
        let none = RolloutArgs::default();
        let got = flag.resolve(Some("2"), Some(3)).unwrap();
        assert_eq!((got.value, got.source), (Some(1), MaxNewSource::Flag));
        let got = none.resolve(Some("2"), Some(3)).unwrap();
        assert_eq!((got.value, got.source), (Some(2), MaxNewSource::Env));
        let got = none.resolve(Some("none"), Some(3)).unwrap();
        assert_eq!((got.value, got.source), (None, MaxNewSource::Env));
        let got = none.resolve(Some(""), Some(3)).unwrap();
        assert_eq!((got.value, got.source), (Some(3), MaxNewSource::File));
        let got = none.resolve(None, None).unwrap();
        assert_eq!((got.value, got.source), (None, MaxNewSource::Default));
        let err = none.resolve(Some("lots"), None).unwrap_err();
        assert!(err.starts_with("SOCKET_MAX_NEW_PATCHES: "), "{err}");
    }
}
